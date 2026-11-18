//go:build !linux && !darwin

package miu

import (
	"errors"
	"net"
	"time"
)

// segmentedCopy is unavailable on this platform: the server reads the target into a buffer instead.
var segmentedCopy = false

// canSegment tells whether readable works on this platform.
const canSegment = false

var errNoSegment = errors.New("miu: not supported on this platform")

func readable(*net.TCPConn, int, time.Time) (int, error) { return 0, errNoSegment }

func peekAt(*net.TCPConn, []byte) (int, error) { return 0, errNoSegment }
