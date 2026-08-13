package mtc

import "testing"

func TestValidTrustAnchorIDBinary(t *testing.T) {
	tests := []struct {
		name string
		id   []byte
		want bool
	}{
		{"example 32473.1", []byte{0x81, 0xfd, 0x59, 0x01}, true},
		{"one zero component", []byte{0x00}, true},
		{"multiple components", []byte{0x01, 0x81, 0x00, 0x7f}, true},
		{"255 one-byte components", make([]byte, 255), true},
		{"empty", nil, false},
		{"unterminated", []byte{0x81}, false},
		{"non-minimal zero group", []byte{0x80, 0x01}, false},
		{"non-minimal zero", []byte{0x80, 0x00}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validTrustAnchorIDBinary(tc.id); got != tc.want {
				t.Fatalf("validTrustAnchorIDBinary(%x) = %t, want %t", tc.id, got, tc.want)
			}
		})
	}
}
