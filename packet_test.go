package packet_test

import (
	"net"
	"testing"

	"github.com/mdlayher/packet"
)

func TestAddrStringNil(t *testing.T) {
	var a *packet.Addr

	if s := a.String(); s != "<nil>" {
		t.Fatalf("unexpected string for nil *Addr: %q", s)
	}

	// net.OpError.Error cannot skip a nil *Addr: its field is an interface,
	// which is non-nil even when the pointer it holds is not.
	err := &net.OpError{
		Op:   "setsockopt",
		Net:  "packet",
		Addr: a,
		Err:  net.UnknownNetworkError("test"),
	}

	if s := err.Error(); s == "" {
		t.Fatal("expected a non-empty error string")
	}
}
