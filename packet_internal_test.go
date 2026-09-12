//go:build linux
// +build linux

package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/josharian/native"
	"golang.org/x/sys/unix"
)

func Test_htons(t *testing.T) {
	tests := []struct {
		name     string
		i        int
		vLE, vBE uint16
		ok       bool
	}{
		{
			name: "negative",
			i:    -1,
		},
		{
			name: "too large",
			i:    math.MaxUint16 + 1,
		},
		{
			name: "IPv4",
			i:    0x0800,
			vLE:  0x0008,
			vBE:  0x0800,
			ok:   true,
		},
		{
			name: "IPv6",
			i:    0x86dd,
			vLE:  0xdd86,
			vBE:  0x86dd,
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := htons(tt.i)
			if tt.ok && err != nil {
				t.Fatalf("failed to perform htons: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			// Depending on our GOARCH, the result may be big or little endian.
			var want uint16
			if native.Endian == binary.ByteOrder(binary.LittleEndian) {
				want = tt.vLE
			} else {
				want = tt.vBE
			}

			if diff := cmp.Diff(hex(want), hex(v)); diff != "" {
				t.Fatalf("unexpected output for %s GOARCH (-want +got):\n%s", native.Endian.String(), diff)
			}
		})
	}
}

func hex(v uint16) string {
	return fmt.Sprintf("%#04x", v)
}

func Test_setPacketMreqAddressTooLong(t *testing.T) {
	tests := []struct {
		name string
		addr net.HardwareAddr
	}{
		{
			name: "one byte too long",
			addr: make(net.HardwareAddr, 9),
		},
		{
			name: "IPoIB",
			addr: make(net.HardwareAddr, 20),
		},
	}

	// The address length is checked before the Conn is used to invoke
	// setsockopt(2), so a Conn which carries nothing but the metadata needed
	// to produce an error suffices, and no privileges are required.
	fns := []struct {
		name string
		fn   func(*Conn, net.HardwareAddr) error
	}{
		{
			name: "joinGroup",
			fn:   (*Conn).joinGroup,
		},
		{
			name: "leaveGroup",
			fn:   (*Conn).leaveGroup,
		},
	}

	for _, tt := range tests {
		for _, fn := range fns {
			t.Run(tt.name+"/"+fn.name, func(t *testing.T) {
				c := &Conn{addr: &Addr{HardwareAddr: make(net.HardwareAddr, 6)}}

				err := fn.fn(c, tt.addr)
				if err == nil {
					t.Fatal("expected an error, but none occurred")
				}
				t.Logf("err: %v", err)

				// The error must carry the package's usual
				// net.OpError(os.SyscallError(unix.Errno)) shape.
				var oerr *net.OpError
				if !errors.As(err, &oerr) {
					t.Fatalf("error was not a *net.OpError: %T", err)
				}
				if diff := cmp.Diff(opSetsockopt, oerr.Op); diff != "" {
					t.Fatalf("unexpected net.OpError Op (-want +got):\n%s", diff)
				}
				if !errors.Is(err, unix.EINVAL) {
					t.Fatalf("expected unix.EINVAL, but got: %v", err)
				}
			})
		}
	}
}
