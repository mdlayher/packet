package packet

import (
	"net"
	"os"
	"syscall"
	"time"

	"github.com/mdlayher/socket"
)

// TODO(mdlayher): pulling in *socket.Conn at the root breaks windows builds;
// this is a slight nuisance but probably worth fixing up here and in vsock.

const (
	// network is the network reported in net.OpError.
	network = "packet"

	// Operation names which may be returned in net.OpError.
	opClose       = "close"
	opListen      = "listen"
	opRawControl  = "raw-control"
	opRawRead     = "raw-read"
	opRawWrite    = "raw-write"
	opRead        = "read"
	opSet         = "set"
	opSyscallConn = "syscall-conn"
	opWrite       = "write"
)

// Config contains options for a Conn.
type Config struct{}

// Type is a socket type used when creating a Conn with Listen.
//enumcheck:exhaustive
type Type int

// Possible Type values. Note that the zero value is not valid: callers must
// always specify one of Raw or Datagram when calling Listen.
const (
	_ Type = iota
	Raw
	Datagram
)

// Listen opens a packet sockets connection on the specified interface, using
// the given socket type and protocol values. The socket type must be one of the
// Type constants: Raw or Datagram.
func Listen(ifi *net.Interface, socketType Type, protocol int, cfg *Config) (*Conn, error) {
	l, err := listen(ifi, socketType, protocol, cfg)
	if err != nil {
		return nil, opError(opListen, err, &Addr{HardwareAddr: ifi.HardwareAddr})
	}

	return l, nil
}

// FileConn returns a copy of the network connection corresponding to an open
// os.File. It is the caller's responsibility to close the Conn when finished.
// Closing the Conn does not affect the os.File, and closing the os.File does
// not affect the Conn.
//
// This function is intended for advanced use cases and most callers should use
// Listen instead.
func FileConn(f *os.File) (*Conn, error) {
	l, err := fileConn(f)
	if err != nil {
		// No addresses available.
		return nil, opError(opListen, err, nil)
	}

	return l, nil
}

var (
	_ net.PacketConn = &Conn{}
	_ syscall.Conn   = &Conn{}
)

// A Conn is an Linux packet sockets (AF_PACKET) implementation of a
// net.PacketConn.
type Conn struct {
	c *socket.Conn

	// Metadata about the local connection.
	addr     *Addr
	ifIndex  int
	protocol uint16
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.opError(opClose, c.c.Close())
}

// LocalAddr returns the local network address. The Addr returned is shared by
// all invocations of LocalAddr, so do not modify it.
func (c *Conn) LocalAddr() net.Addr { return c.addr }

// ReadFrom implements the net.PacketConn ReadFrom method.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	// From net.PacketConn documentation:
	//
	// "[ReadFrom] returns the number of bytes read (0 <= n <= len(p)) and any
	// error encountered. Callers should always process the n > 0 bytes returned
	// before considering the error err."
	//
	// Every error return should always return all the information we have.
	n, sa, err := c.c.Recvfrom(b, 0)
	if err != nil {
		return n, nil, c.opError(opRead, err)
	}

	return n, fromSockaddr(sa), nil
}

// WriteTo implements the net.PacketConn WriteTo method.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	sa, err := toSockaddr("sendto", addr, c.ifIndex, c.protocol)
	if err != nil {
		return 0, c.opError(opWrite, err)
	}

	// From packet(7):
	//
	// "When you send packets it is enough to specify sll_family, sll_addr,
	// sll_halen, sll_ifindex, and sll_protocol. The other fields should be 0."
	//
	// sll_family is set on the conversion to unix.RawSockaddrLinklayer.
	//
	// TODO(mdlayher): it's curious that unix.Sendto does not return the number
	// of bytes actually sent. Fake it for now, but investigate upstream.
	if err := c.c.Sendto(b, sa, 0); err != nil {
		return 0, c.opError(opWrite, err)
	}

	return len(b), nil
}

// SetDeadline implements the net.PacketConn SetDeadline method.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.opError(opSet, c.c.SetDeadline(t))
}

// SetReadDeadline implements the net.PacketConn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.opError(opSet, c.c.SetReadDeadline(t))
}

// SetWriteDeadline implements the net.PacketConn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.opError(opSet, c.c.SetWriteDeadline(t))
}

// SyscallConn returns a raw network connection. This implements the
// syscall.Conn interface.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	rc, err := c.c.SyscallConn()
	if err != nil {
		return nil, c.opError(opSyscallConn, err)
	}

	return &rawConn{
		rc:   rc,
		addr: c.addr,
	}, nil
}

// opError is a convenience for the function opError that also passes the local
// and remote addresses of the Conn.
func (c *Conn) opError(op string, err error) error {
	return opError(op, err, c.addr)
}

// TODO(mdlayher): see if we can port smarter net.OpError logic into
// socket.Conn's SyscallConn type to avoid the need for this wrapper.

var _ syscall.RawConn = &rawConn{}

// A rawConn is a syscall.RawConn that wraps an internal syscall.RawConn in order
// to produce net.OpError error values.
type rawConn struct {
	rc   syscall.RawConn
	addr *Addr
}

// Control implements the syscall.RawConn Control method.
func (rc *rawConn) Control(fn func(fd uintptr)) error {
	return rc.opError(opRawControl, rc.rc.Control(fn))
}

// Control implements the syscall.RawConn Read method.
func (rc *rawConn) Read(fn func(fd uintptr) (done bool)) error {
	return rc.opError(opRawRead, rc.rc.Read(fn))
}

// Control implements the syscall.RawConn Write method.
func (rc *rawConn) Write(fn func(fd uintptr) (done bool)) error {
	return rc.opError(opRawWrite, rc.rc.Write(fn))
}

// opError is a convenience for the function opError that also passes the
// address of the rawConn.
func (rc *rawConn) opError(op string, err error) error {
	return opError(op, err, rc.addr)
}

var _ net.Addr = &Addr{}

// TODO(mdlayher): expose sll_hatype and sll_pkttype on receive Addr only.

// An Addr is a physical-layer address.
type Addr struct {
	HardwareAddr net.HardwareAddr
}

// Network returns the address's network name, "packet".
func (a *Addr) Network() string { return network }

// String returns the string representation of an Addr.
func (a *Addr) String() string {
	return a.HardwareAddr.String()
}

// opError unpacks err if possible, producing a net.OpError with the input
// parameters in order to implement net.PacketConn. As a convenience, opError
// returns nil if the input error is nil.
func opError(op string, err error, local net.Addr) error {
	if err == nil {
		return nil
	}

	// TODO(mdlayher): try to comply with net.PacketConn as best as we can; land
	// a nettest.TestPacketConn API upstream.
	return &net.OpError{
		Op:   op,
		Net:  network,
		Addr: local,
		Err:  err,
	}
}
