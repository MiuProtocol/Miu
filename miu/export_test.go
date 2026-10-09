package miu

// SetTestObserver installs the test hook that reports which code paths were taken; nil removes it.
func SetTestObserver(f func(event string)) {
	if f == nil {
		testObserver.Store(nil)
		return
	}
	testObserver.Store(&f)
}

// SetSegmentedCopy switches the server's segmented downlink on or off and returns the previous setting.
func SetSegmentedCopy(on bool) (old bool) {
	old, segmentedCopy = segmentedCopy, on
	return old
}

// CanSegment reports whether this platform can run the segmented downlink at all.
func CanSegment() bool { return canSegment }
