package mtc

import (
	"math/big"
	"math/bits"
)

func ValidSubtree(start, end uint64) bool {
	if start >= end || end > (1<<48)-1 {
		return false
	}
	width := end - start
	ceil := uint64(1) << bits.Len64(width-1)
	return start%ceil == 0
}

func SplitSerial(n *big.Int) (uint16, uint64, bool) {
	if n == nil || n.Sign() <= 0 || n.BitLen() > 64 {
		return 0, 0, false
	}
	v := n.Uint64()
	logNumber := uint16(v >> 48)
	return logNumber, v & ((1 << 48) - 1), true
}
