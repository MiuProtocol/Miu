package miu

import (
	"syscall"
	"unsafe"
)

// segmentedCopy enables the "declare what is buffered, then copy exactly that" downlink of the server.
// On Linux the copy between two TCP connections is a splice, so the bytes never enter user space.
var segmentedCopy = true

// canSegment tells whether readable works on this platform.
const canSegment = true

// inq returns how many bytes sit in the receive buffer of the socket fd.
func inq(fd uintptr) (int, error) {
	var v int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&v))); e != 0 {
		return 0, e
	}
	return int(v), nil
}
