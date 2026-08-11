package mtc_test

import (
	"math/big"
	"testing"

	"github.com/pkimetal/pkimetal/mtc"
)

func TestValidSubtree(t *testing.T) {
	maxUint48 := uint64(1<<48) - 1
	for _, tc := range []struct {
		name       string
		start, end uint64
		want       bool
	}{
		{"single entry", 0, 1, true},
		{"power of two", 4, 8, true},
		{"rounded width", 8, 13, true},
		{"misaligned rounded width", 4, 9, false},
		{"misaligned power of two", 5, 8, false},
		{"empty", 8, 8, false},
		{"reversed", 9, 8, false},
		{"maximum end", maxUint48 - 1, maxUint48, true},
		{"end outside uint48", maxUint48, maxUint48 + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mtc.ValidSubtree(tc.start, tc.end); got != tc.want {
				t.Errorf("ValidSubtree(%d, %d) = %t, want %t", tc.start, tc.end, got, tc.want)
			}
		})
	}
}

func TestSplitSerial(t *testing.T) {
	logNumber, index, ok := mtc.SplitSerial(new(big.Int).SetUint64((7 << 48) | 42))
	if !ok || logNumber != 7 || index != 42 {
		t.Fatalf("SplitSerial = (%d, %d, %t)", logNumber, index, ok)
	}

	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	for _, serial := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), tooLarge} {
		logNumber, index, ok = mtc.SplitSerial(serial)
		if ok || logNumber != 0 || index != 0 {
			t.Errorf("SplitSerial(%v) = (%d, %d, %t), want (0, 0, false)", serial, logNumber, index, ok)
		}
	}
}
