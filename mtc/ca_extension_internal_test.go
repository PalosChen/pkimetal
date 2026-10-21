package mtc

import (
	"bytes"
	"runtime"
	"testing"
)

const maxOversizedCAIDParseAllocation = 256 << 10

var (
	caIDAllocationResult []byte
	caIDAllocationError  error
)

func TestEncodeRelativeOIDRejectsHugeArcWithoutLargeAllocation(t *testing.T) {
	text := bytes.Repeat([]byte{'9'}, 4<<20)

	allocated := allocatedBytesForCAIDParse(text)
	if caIDAllocationError == nil {
		t.Fatal("accepted a multi-megabyte decimal arc")
	}
	if allocated > maxOversizedCAIDParseAllocation {
		t.Fatalf("oversized decimal arc allocated %d bytes, want at most %d", allocated, maxOversizedCAIDParseAllocation)
	}
}

func TestEncodeRelativeOIDRejectsHugeArcListWithoutLargeAllocation(t *testing.T) {
	text := bytes.Repeat([]byte("1."), 1<<20)

	allocated := allocatedBytesForCAIDParse(text)
	if caIDAllocationError == nil {
		t.Fatal("accepted a multi-megabyte arc list")
	}
	if allocated > maxOversizedCAIDParseAllocation {
		t.Fatalf("oversized arc list allocated %d bytes, want at most %d", allocated, maxOversizedCAIDParseAllocation)
	}
}

func allocatedBytesForCAIDParse(text []byte) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	caIDAllocationResult, caIDAllocationError = encodeRelativeOID(text)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
