//go:build !linux
// +build !linux

package packet

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// errUnimplemented is returned by all functions on non-Linux platforms.
var errUnimplemented = fmt.Errorf("packet: not implemented on %s", runtime.GOOS)

func fileConn(_ *os.File) (*Conn, error)                               { return nil, errUnimplemented }
func listen(_ *net.Interface, _ Type, _ int, _ *Config) (*Conn, error) { return nil, errUnimplemented }

func fromSockaddr(_ unix.Sockaddr) *Addr { return nil }
func toSockaddr(_ string, _ net.Addr, _ int, _ uint16) (unix.Sockaddr, error) {
	return nil, errUnimplemented
}
