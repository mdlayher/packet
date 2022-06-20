// go:build darwin
//go:build darwin
// +build darwin

package packet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func listen(ifi *net.Interface, socketType Type, protocol int, cfg *Config) (*Conn, error) {
	var f *os.File
	var err error

	if cfg == nil {
		// Default config
		cfg = &Config{}
	}

	// Try to find an available BPF device
	for i := 0; i <= 255; i++ {
		bpfPath := fmt.Sprintf("/dev/bpf%d", i)
		f, err = os.OpenFile(bpfPath, os.O_RDWR, 0666)
		if err == nil {
			// Found a usable device
			break
		}

		// Device is busy, try the next one
		if perr, ok := err.(*os.PathError); ok {
			if perr.Err.(syscall.Errno) == syscall.EBUSY {
				continue
			}
		}

		return nil, err
	}

	if f == nil {
		return nil, errors.New("unable to open BPF device")
	}

	fd := int(f.Fd())
	if fd == -1 {
		return nil, errors.New("unable to open BPF device")
	}

	proto := uint16(protocol)

	// Configure BPF device to send and receive data
	buflen, err := configureBPF(fd, ifi, proto, cfg.Direction)
	if err != nil {
		return nil, err
	}

	return &Conn{
		c: &conn{
			protocol: proto,
			ifi:      ifi,
			f:        f,
			fd:       fd,
			buflen:   buflen,
		},
		protocol: proto,
	}, nil
}

// Maximum read timeout per syscall.
// It is required because read/recvfrom won't be interrupted on closing of the file descriptor.
const readTimeout = 200 * time.Millisecond

func (c *Conn) readFrom(b []byte) (int, net.Addr, error) {
	c.c.timeoutMu.Lock()
	deadline := c.c.rtimeout
	c.c.timeoutMu.Unlock()

	buf := make([]byte, c.c.buflen)
	var n int

	for {
		var timeout time.Duration

		if deadline.IsZero() {
			timeout = readTimeout
		} else {
			timeout = time.Until(deadline)
			if timeout > readTimeout {
				timeout = readTimeout
			}
		}

		tv := unix.NsecToTimeval(timeout.Nanoseconds())
		if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.c.fd), syscall.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(&tv))); err != 0 {
			return 0, nil, syscall.Errno(err)
		}

		// Attempt to receive on socket
		// The read sycall will NOT be interrupted by closing of the socket
		var err error
		n, err = syscall.Read(c.c.fd, buf)
		if err != nil {
			return n, nil, err
		}
		if n > 0 {
			break
		}
	}

	// TODO(synfinatic): consider parsing BPF header if it proves useful.
	// BPF header length depends on the platform this code is running on
	bpfl := bpfLen()

	// Retrieve source MAC address of ethernet header
	mac := make(net.HardwareAddr, 6)
	copy(mac, buf[bpfl+6:bpfl+12])

	// Skip past BPF header to retrieve ethernet frame
	out := copy(b, buf[bpfl:bpfl+n])

	return out, &Addr{
		HardwareAddr: mac,
	}, nil
}

func (c *Conn) writeTo(b []byte, _ net.Addr) (int, error) {
	return syscall.Write(c.c.fd, b)
}

func (c *Conn) setPromiscuous(b bool) error {
	m := 1
	if !b {
		m = 0
	}

	return syscall.SetBpfPromisc(c.c.fd, m)
}

func (c *Conn) stats() (*Stats, error) {
	return nil, errUnimplemented
}

type conn struct {
	protocol uint16
	ifi      *net.Interface
	f        *os.File
	fd       int
	buflen   int

	// Timeouts set via Set{Read,}Deadline, guarded by mutex
	timeoutMu sync.RWMutex
	rtimeout  time.Time
}

func (c *conn) Close() error {
	return c.f.Close()
}

func (c *conn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.timeoutMu.Lock()
	c.rtimeout = t
	c.timeoutMu.Unlock()
	return nil
}

func (*conn) SetWriteDeadline(_ time.Time) error {
	return errUnimplemented
}

func (c *conn) SetBPF(filter []bpf.RawInstruction) error {
	// Base filter filters traffic based on EtherType
	base, err := bpf.Assemble(baseFilter(c.protocol))
	if err != nil {
		return err
	}

	// Append user filter to base filter, translate to raw format,
	// and apply to BPF device
	return syscall.SetBpf(c.fd, assembleBpfInsn(append(base, filter...)))
}

func (*conn) SyscallConn() (syscall.RawConn, error) {
	return nil, errUnimplemented
}

// configureBPF configures a BPF device with the specified file descriptor to
// use the specified network and interface and protocol.
func configureBPF(fd int, ifi *net.Interface, proto uint16, direction Direction) (int, error) {
	// Use specified interface with BPF device
	if err := syscall.SetBpfInterface(fd, ifi.Name); err != nil {
		return 0, err
	}

	// Inform BPF to send us its data immediately
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		return 0, err
	}

	// Check buffer size of BPF device
	buflen, err := syscall.BpfBuflen(fd)
	if err != nil {
		return 0, err
	}

	// Do not automatically complete source address in ethernet headers
	if err := syscall.SetBpfHeadercmpl(fd, 1); err != nil {
		return 0, err
	}

	// Specify incoming only or bidirectional traffic using BPF device
	if err := setBPFDirection(fd, direction); err != nil {
		return 0, err
	}

	// Build and apply base BPF filter which checks for correct EtherType
	// on incoming packets
	prog, err := bpf.Assemble(baseInterfaceFilter(proto, ifi.MTU))
	if err != nil {
		return 0, err
	}
	if err := syscall.SetBpf(fd, assembleBpfInsn(prog)); err != nil {
		return 0, err
	}

	// Flush any packets currently in the BPF device's buffer
	if err := syscall.FlushBpf(fd); err != nil {
		return 0, err
	}

	return buflen, nil
}

// assembleBpfInsn assembles a slice of bpf.RawInstructions to the format required by
// package syscall.
func assembleBpfInsn(filter []bpf.RawInstruction) []syscall.BpfInsn {
	// Copy each bpf.RawInstruction into syscall.BpfInsn.  If needed,
	// the structures have the same memory layout and could probably be
	// unsafely cast to each other for speed.
	insns := make([]syscall.BpfInsn, 0, len(filter))
	for _, ins := range filter {
		insns = append(insns, syscall.BpfInsn{
			Code: ins.Op,
			Jt:   ins.Jt,
			Jf:   ins.Jf,
			K:    ins.K,
		})
	}

	return insns
}

// baseInterfaceFilter creates a base BPF filter which filters traffic based
// on its EtherType and returns up to "mtu" bytes of data for processing.
func baseInterfaceFilter(proto uint16, mtu int) []bpf.Instruction {
	return append(
		// Filter traffic based on EtherType
		baseFilter(proto),
		// Accept the packet bytes up to the interface's MTU
		bpf.RetConstant{
			Val: uint32(mtu),
		},
	)
}

// baseFilter creates a base BPF filter which filters traffic based on its
// EtherType.  baseFilter can be prepended to other filters to handle common
// filtering tasks.
func baseFilter(proto uint16) []bpf.Instruction {
	// Offset | Length | Comment
	// -------------------------
	//   00   |   06   | Ethernet destination MAC address
	//   06   |   06   | Ethernet source MAC address
	//   12   |   02   | Ethernet EtherType
	const (
		etherTypeOffset = 12
		etherTypeLength = 2
	)

	return []bpf.Instruction{
		// Load EtherType value from Ethernet header
		bpf.LoadAbsolute{
			Off:  etherTypeOffset,
			Size: etherTypeLength,
		},
		// If EtherType is equal to the protocol we are using, jump to instructions
		// added outside of this function.
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      uint32(proto),
			SkipTrue: 1,
		},
		// EtherType does not match our protocol
		bpf.RetConstant{
			Val: 0,
		},
	}
}

// bpfLen returns the length of the BPF header prepended to each incoming ethernet
// frame.  FreeBSD uses a slightly modified header from other BSD variants.
func bpfLen() int {
	// Majority of BSD family systems use the bpf_hdr struct, but FreeBSD
	// has replaced this with bpf_xhdr, which is longer.
	const (
		bpfHeaderLen  = 18
		bpfXHeaderLen = 26
	)

	if runtime.GOOS == "freebsd" {
		return bpfXHeaderLen
	}

	return bpfHeaderLen
}
