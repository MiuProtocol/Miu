//go:build linux || darwin

package miu

import (
	"io"
	"net"
	"syscall"
	"time"
)

// readable waits until at least min bytes sit in c's receive buffer and returns how many there are,
// without taking any. It returns io.EOF once the peer has closed its side and nothing is left, and
// os.ErrDeadlineExceeded when deadline (if set) passes first.
func readable(c *net.TCPConn, min int, deadline time.Time) (n int, err error) {
	if !deadline.IsZero() {
		_ = c.SetReadDeadline(deadline)
		defer c.SetReadDeadline(time.Time{})
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	rerr := rc.Read(func(fd uintptr) bool {
		v, e := inq(fd)
		switch {
		case e != nil:
			err = e
			return true
		case v >= min:
			n = v
			return true
		case v > 0:
			return false // wait for more
		}
		// An empty buffer: tell waiting apart from the end of the stream.
		var b [1]byte
		r, _, e := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR:
			return false
		case e != nil:
			err = e
		case r == 0:
			err = io.EOF
		case r >= min:
			n = r // data arrived between the two calls
		default:
			return false
		}
		return true
	})
	if rerr != nil {
		return 0, rerr
	}
	return n, err
}

// peekAt copies what is waiting in c's receive buffer into p, at most len(p) bytes, without taking it.
func peekAt(c *net.TCPConn, p []byte) (n int, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	rerr := rc.Read(func(fd uintptr) bool {
		r, _, e := syscall.Recvfrom(int(fd), p, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR:
			return false
		case e != nil:
			err = e
		case r == 0:
			err = io.EOF
		default:
			n = r
		}
		return true
	})
	if rerr != nil {
		return 0, rerr
	}
	return n, err
}
