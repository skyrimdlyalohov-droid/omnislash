package omnislash

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *stateConn) ConnectionState() tls.ConnectionState { return c.state }

type utlsStateConn struct {
	net.Conn
	state utls.ConnectionState
}

func (c *utlsStateConn) ConnectionState() utls.ConnectionState { return c.state }

func TestTTFBConnForwardsConnectionState(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()

	wrapped := newTTFBConn(&stateConn{Conn: raw, state: tls.ConnectionState{NegotiatedProtocol: "h2"}}, time.Second)
	state, ok := wrapped.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		t.Fatal("TTFB guard dropped ConnectionState")
	}
	if got := state.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("ALPN after TTFB guard = %q, want h2", got)
	}

	plain := newTTFBConn(raw, time.Second)
	state, ok = plain.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		t.Fatal("TTFB guard dropped ConnectionState for a plain conn")
	}
	if got := state.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("plain conn ALPN = %q, want empty", got)
	}

	// Fingerprinted sessions expose uTLS's own ConnectionState type. It must be
	// converted, otherwise H2 probes silently see an empty ALPN.
	fp := newTTFBConn(&utlsStateConn{Conn: raw, state: utls.ConnectionState{NegotiatedProtocol: "h2", HandshakeComplete: true}}, time.Second)
	got, ok := TLSState(fp)
	if !ok || got.NegotiatedProtocol != "h2" || !got.HandshakeComplete {
		t.Fatalf("uTLS state through TTFB guard = %+v, ok=%v", got, ok)
	}
}
