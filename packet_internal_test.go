//go:build linux
// +build linux

package packet

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/josharian/native"
)

func Test_htons(t *testing.T) {
	tests := []struct {
		name     string
		i        int
		vLE, vBE uint16
		ok       bool
	}{
		{
			name: "negative",
			i:    -1,
		},
		{
			name: "too large",
			i:    math.MaxUint16 + 1,
		},
		{
			name: "IPv4",
			i:    0x0800,
			vLE:  0x0008,
			vBE:  0x0800,
			ok:   true,
		},
		{
			name: "IPv6",
			i:    0x86dd,
			vLE:  0xdd86,
			vBE:  0x86dd,
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := htons(tt.i)
			if tt.ok && err != nil {
				t.Fatalf("failed to perform htons: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			// Depending on our GOARCH, the result may be big or little endian.
			var want uint16
			if native.Endian == binary.ByteOrder(binary.LittleEndian) {
				want = tt.vLE
			} else {
				want = tt.vBE
			}

			if diff := cmp.Diff(hex(want), hex(v)); diff != "" {
				t.Fatalf("unexpected output for %s GOARCH (-want +got):\n%s", native.Endian.String(), diff)
			}
		})
	}
}

func hex(v uint16) string {
	return fmt.Sprintf("%#04x", v)
}
