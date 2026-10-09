package miu

import (
	"io"
	"net"
	"syscall"
	"unsafe"
)

// segmentedCopy enables the "declare what is buffered, then copy exactly that" downlink of the server.
// On Linux the copy between two TCP connections is a splice, so the bytes never enter user space.
var segmentedCopy = true

// canSegment tells whether readable works on this platform.
const canSegment = true

// readable waits until c has data to read and returns how many bytes sit in its receive buffer, without
// taking any. It returns io.EOF once the peer has closed its side.
func readable(c *net.TCPConn) (n int, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	rerr := rc.Read(func(fd uintptr) bool {
		var v int32
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&v))); e != 0 {
			err = e
			return true
		}
		if v > 0 {
			n = int(v)
			return true
		}
		return peekReadable(fd, &n, &err)
	})
	if rerr != nil {
		return 0, rerr
	}
	return n, err
}

// peekReadable tells an empty buffer apart from the end of the stream. It returns false to keep waiting.
func peekReadable(fd uintptr, n *int, err *error) bool {
	var b [1]byte
	r, _, e := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
	switch {
	case e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR:
		return false
	case e != nil:
		*err = e
	case r == 0:
		*err = io.EOF
	default:
		*n = r // data arrived between the two calls
	}
	return true
}
