//go:build go1.16
// +build go1.16

// Just because the library builds and runs on older versions of Go doesn't mean
// we have to apply the same restrictions for tests. Go 1.16 is the oldest
// upstream supported version of Go as of February 2022.

package packet_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

func TestConnListen(t *testing.T) {
	// Open a connection on an Ethernet interface and begin listening for
	// incoming Ethernet frames. We assume that this interface will receive some
	// sort of traffic in the next 30 seconds and we will capture that traffic
	// by looking for any EtherType value (ETH_P_ALL).
	c, ifi := testConn(t)
	t.Logf("interface: %q, MTU: %d", ifi.Name, ifi.MTU)

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	b := make([]byte, ifi.MTU)
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		t.Fatalf("failed to read Ethernet frame: %v", err)
	}

	// Received some data, assume some Stats were populated.
	stats, err := c.Stats()
	if err != nil {
		t.Fatalf("failed to fetch stats: %v", err)
	}
	if stats.Packets == 0 {
		t.Fatal("stats indicated 0 received packets")
	}

	t.Logf("  - packets: %d, drops: %d, freeze queue count: %d",
		stats.Packets, stats.Drops, stats.FreezeQueueCount)

	// TODO(mdlayher): we could import github.com/mdlayher/ethernet, but parsing
	// an Ethernet frame header is fairly easy and this keeps the go.mod tidy.

	// Need at least destination MAC, source MAC, and EtherType.
	const header = 6 + 6 + 2
	if n < header {
		t.Fatalf("did not read a complete Ethernet frame from %v, only %d bytes read",
			addr, n)
	}

	// Parse the header to provide tidy log output.
	var (
		dst = net.HardwareAddr(b[0:6])
		src = net.HardwareAddr(b[6:12])
		et  = binary.BigEndian.Uint16(b[12:14])
	)

	// Check for the most likely EtherType values.
	var ets string
	switch et {
	case 0x0800:
		ets = "IPv4"
	case 0x0806:
		ets = "ARP"
	case 0x86dd:
		ets = "IPv6"
	default:
		ets = "unknown"
	}

	// And finally print what we found for the user.
	t.Log("Ethernet frame:")
	t.Logf("  - destination: %s", dst)
	t.Logf("  -      source: %s", src)
	t.Logf("  -   ethertype: %#04x (%s)", et, ets)
	t.Logf("  -     payload: %d bytes", n-header)
}

func TestConnJoinLeaveGroup(t *testing.T) {
	// A synthetic group address: the multicast bit is set in the first octet,
	// but the address is not one which any real protocol would use, so it is
	// very unlikely to already be joined on the test interface.
	group := net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}

	// Note that this test deliberately does not check whether traffic destined
	// for the group is received: a join cannot be verified that way because
	// some interface types (such as veth) do not filter multicast traffic at
	// all, and thus such a test would pass whether or not the join actually
	// took place. Query the kernel for the interface's group memberships
	// instead; see testMaddrs.
	c, ifi := testConn(t)
	maddrs := testMaddrs(t, ifi)

	if maddrs(group) {
		t.Skipf("skipping, group %s is already joined on %q", group, ifi.Name)
	}

	if err := c.JoinGroup(group); err != nil {
		t.Fatalf("failed to join group: %v", err)
	}
	if !maddrs(group) {
		t.Fatalf("group %s was not joined on %q", group, ifi.Name)
	}

	// Memberships are reference counted per socket, as documented on
	// Conn.JoinGroup: a second join requires a second leave.
	if err := c.JoinGroup(group); err != nil {
		t.Fatalf("failed to join group again: %v", err)
	}
	if err := c.LeaveGroup(group); err != nil {
		t.Fatalf("failed to leave group: %v", err)
	}
	if !maddrs(group) {
		t.Fatalf("group %s was dropped on %q after only one of two leaves",
			group, ifi.Name)
	}

	if err := c.LeaveGroup(group); err != nil {
		t.Fatalf("failed to leave group again: %v", err)
	}
	if maddrs(group) {
		t.Fatalf("group %s was still joined on %q after leaving", group, ifi.Name)
	}
}

// testMaddrs produces a function which reports whether the input address is
// presently joined as a link layer multicast group on the input interface,
// according to the Linux kernel.
func testMaddrs(t *testing.T, ifi *net.Interface) func(net.HardwareAddr) bool {
	t.Helper()

	// The kernel exposes each network interface's link layer multicast group
	// memberships in /proc/net/dev_mcast, which requires no privileges to
	// read. Note that rtnetlink is not an option here: RTM_GETMULTICAST only
	// reports IPv4 and IPv6 multicast addresses, and a group joined by a
	// packet socket need not have any IP address associated with it at all.
	// This is also why iproute2 reads the same file for "ip maddr show".
	return func(addr net.HardwareAddr) bool {
		t.Helper()

		b, err := os.ReadFile("/proc/net/dev_mcast")
		if err != nil {
			t.Fatalf("failed to read multicast group memberships: %v", err)
		}

		// Each line is of the form:
		//   "2    eth0            1     0     01005e000001"
		// being the interface index and name, a reference count, a flag for
		// whether the address was set globally, and finally the hardware
		// address in hexadecimal with no separators.
		want := hex.EncodeToString(addr)

		for _, s := range strings.Split(string(b), "\n") {
			fields := strings.Fields(s)
			if len(fields) < 5 || fields[1] != ifi.Name {
				continue
			}

			if strings.EqualFold(fields[4], want) {
				return true
			}
		}

		return false
	}
}

// testConn produces a *packet.Conn bound to the returned *net.Interface. The
// caller does not need to call Close on the *packet.Conn.
func testConn(t *testing.T) (*packet.Conn, *net.Interface) {
	t.Helper()

	// TODO(mdlayher): probably parameterize the EtherType.
	ifi := testInterface(t)
	c, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied (try setting CAP_NET_RAW capability): %v", err)
		}

		t.Fatalf("failed to listen: %v", err)
	}

	t.Cleanup(func() { c.Close() })
	return c, ifi
}

// testInterface looks for a suitable Ethernet interface to bind a *packet.Conn.
func testInterface(t *testing.T) *net.Interface {
	ifis, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to get network interfaces: %v", err)
	}

	if len(ifis) == 0 {
		t.Skip("skipping, no network interfaces found")
	}

	// Try to find a suitable network interface for tests.
	var tried []string
	for _, ifi := range ifis {
		tried = append(tried, ifi.Name)

		// true is used to line up other checks.
		ok := true &&
			// Look for an Ethernet interface.
			len(ifi.HardwareAddr) == 6 &&
			// Look for up, multicast, broadcast.
			ifi.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0

		if ok {
			return &ifi
		}
	}

	t.Skipf("skipping, could not find a usable network interface, tried: %s", tried)
	panic("unreachable")
}
