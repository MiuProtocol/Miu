//go:build !linux && !darwin

package miu

import (
	"errors"
	"net"
)

// segmentedCopy is unavailable on this platform: the server reads the target into a buffer instead.
var segmentedCopy = false

// canSegment tells whether readable works on this platform.
const canSegment = false

func readable(*net.TCPConn) (int, error) { return 0, errors.New("miu: not supported on this platform") }
