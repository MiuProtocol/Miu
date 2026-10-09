package miu

import (
	"io"
	"net"
	"syscall"
)

// segmentedCopy is off by default here: without splice the segmented downlink has no advantage over
// reading into a buffer. The code path is the same as on Linux and the tests switch it on.
var segmentedCopy = false

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
		v, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NREAD)
		if e != nil {
			err = e
			return true
		}
		if v > 0 {
			n = v
			return true
		}
		var b [1]byte
		r, _, e := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR:
			return false
		case e != nil:
			err = e
		case r == 0:
			err = io.EOF
		default:
			n = r // data arrived between the two calls
		}
		return true
	})
	if rerr != nil {
		return 0, rerr
	}
	return n, err
}
