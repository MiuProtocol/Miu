package miu

import "syscall"

// segmentedCopy is off by default here: without splice the segmented downlink has no advantage over
// reading into a buffer. The code path is the same as on Linux and the tests switch it on.
var segmentedCopy = false

// canSegment tells whether readable works on this platform.
const canSegment = true

// inq returns how many bytes sit in the receive buffer of the socket fd.
func inq(fd uintptr) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NREAD)
}
