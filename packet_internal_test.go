//go:build linux
// +build linux

package packet

import (
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/cpu"
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
			if cpu.IsBigEndian {
				want = tt.vBE
			} else {
				want = tt.vLE
			}

			if diff := cmp.Diff(hex(want), hex(v)); diff != "" {
				t.Fatalf("unexpected output for big endian %v GOARCH (-want +got):\n%s", cpu.IsBigEndian, diff)
			}
		})
	}
}

func hex(v uint16) string {
	return fmt.Sprintf("%#04x", v)
}
