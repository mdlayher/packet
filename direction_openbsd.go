//go:build openbsd
// +build openbsd

package packet

import (
	"runtime"
	"syscall"
	"unsafe"
)

// setBPFDirection enables filtering traffic traveling in a specific direction
// using BPF, so that traffic sent by this package is not captured when reading
// using this package.
func setBPFDirection(fd int, direction Direction) error {
	var dirfilt uint

	switch direction {
	case DirectionIn:
		return new.Error("DirectionIn is not supported on %s", runtime.GOOS)
	case DirectionInOut:
		dirfilt = 1
	case DirectionOut:
		dirfilt = 0
	}

	switch direction {
	case 0:
		// filter outbound
		dirfilt = syscall.BPF_DIRECTION_OUT
	default:
		// no filter
	}

	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.BIOCSDIRFILT,
		uintptr(unsafe.Pointer(&dirfilt)),
	)
	if err != 0 {
		return syscall.Errno(err)
	}

	return nil
}
