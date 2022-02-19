//go:build linux
// +build linux

package packet

import (
	"errors"
	"math"
	"net"
	"os"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

// listen is the entry point for Listen on Linux.
func listen(ifi *net.Interface, socketType Type, protocol int, _ *Config) (*Conn, error) {
	// TODO(mdlayher): Config default nil check and initialize. Pass options to
	// socket.Config where necessary.

	// Convert Type to the matching SOCK_* constant.
	var typ int
	switch socketType {
	case Raw:
		typ = unix.SOCK_RAW
	case Datagram:
		typ = unix.SOCK_DGRAM
	default:
		return nil, errors.New("packet: invalid Type value")
	}

	// Protocol is intentionally zero in call to socket(2); we can set it on
	// bind(2) instead. Package raw notes: "Do not specify a protocol to avoid
	// capturing packets which to not match cfg.Filter."
	c, err := socket.Socket(unix.AF_PACKET, typ, 0, network, nil)
	if err != nil {
		return nil, err
	}

	conn, err := bind(c, ifi.Index, protocol)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return conn, nil
}

// bind binds the *socket.Conn to finalize *Conn setup.
func bind(c *socket.Conn, ifIndex, protocol int) (*Conn, error) {
	// packet(7) says we sll_protocol must be in network byte order.
	pnet, err := htons(protocol)
	if err != nil {
		return nil, err
	}

	// TODO(mdlayher): investigate the possibility of sll_ifindex = 0 because we
	// could bind to any interface.
	err = c.Bind(&unix.SockaddrLinklayer{
		Protocol: pnet,
		Ifindex:  ifIndex,
	})
	if err != nil {
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		return nil, err
	}

	// Parse the physical layer address; sll_halen tells us how many bytes of
	// sll_addr we should treat as valid.
	lsall := lsa.(*unix.SockaddrLinklayer)
	addr := make(net.HardwareAddr, lsall.Halen)
	copy(addr, lsall.Addr[:])

	return &Conn{
		c: c,

		addr:     &Addr{HardwareAddr: addr},
		ifIndex:  ifIndex,
		protocol: pnet,
	}, nil
}

// fileConn is the entry point for FileConn on Linux.
func fileConn(f *os.File) (*Conn, error) {
	panic("todo")
}

// fromSockaddr converts an opaque unix.Sockaddr to *Addr. It panics if sa is
// not of type *unix.SockaddrLinklayer.
func fromSockaddr(sa unix.Sockaddr) *Addr {
	sall := sa.(*unix.SockaddrLinklayer)

	return &Addr{
		// The syscall already allocated sa; just slice into it with the
		// appropriate length and type conversion rather than making a copy.
		HardwareAddr: net.HardwareAddr(sall.Addr[:sall.Halen]),
	}
}

// toSockaddr converts a net.Addr to an opaque unix.Sockaddr. It returns an
// error if the fields cannot be packed into a *unix.SockaddrLinklayer.
func toSockaddr(
	op string,
	addr net.Addr,
	ifIndex int,
	protocol uint16,
) (unix.Sockaddr, error) {
	// The typical error convention for net.Conn types is
	// net.OpError(os.SyscallError(syscall.Errno)), so all calls here should
	// return os.SyscallError(syscall.Errno) so the caller can apply the final
	// net.OpError wrapper.

	// Ensure the correct Addr type.
	a, ok := addr.(*Addr)
	if !ok || a.HardwareAddr == nil {
		return nil, os.NewSyscallError(op, unix.EINVAL)
	}

	// Pack Addr and Conn metadata into the appropriate sockaddr fields.
	sa := unix.SockaddrLinklayer{
		Ifindex:  ifIndex,
		Protocol: protocol,
	}

	// Ensure the input address does not exceed the amount of space available;
	// for example an IPoIB address is 20 bytes.
	if len(a.HardwareAddr) > len(sa.Addr) {
		return nil, os.NewSyscallError(op, unix.EINVAL)
	}

	sa.Halen = uint8(len(a.HardwareAddr))
	copy(sa.Addr[:], a.HardwareAddr)

	return &sa, nil
}

// htons converts a short (uint16) from host-to-network byte order. Thanks to
// mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i int) (uint16, error) {
	if i > math.MaxUint16 {
		return 0, errors.New("packet: protocol value out of range")
	}

	v := uint16(i)
	return (v<<8)&0xff00 | v>>8, nil
}
