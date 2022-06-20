//go:build darwin || dragonfly || freebsd || netbsd
// +build darwin dragonfly freebsd netbsd

package packet

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// setBPFDirection enables filtering traffic traveling in a specific direction
// using BPF, so that traffic sent by this package is not captured when reading
// using this package.
func setBPFDirection(fd int, direction Direction) error {
	var dirfilt int

	switch direction {
	case DirectionIn:
		dirfilt = 0
	case DirectionInOut:
		dirfilt = 1
	case DirectionOut:
		return fmt.Errorf("DirectionOut is not supported on %s", runtime.GOOS)
	}

	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		// Even though BIOCSDIRECTION is preferred on FreeBSD, BIOCSSEESENT continues
		// to work, and is required for other BSD platforms
		syscall.BIOCSSEESENT,
		uintptr(unsafe.Pointer(&dirfilt)),
	)
	if err != 0 {
		return syscall.Errno(err)
	}

	return nil
}
