package probe

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

type h2StateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *h2StateConn) ConnectionState() tls.ConnectionState { return c.state }

func TestCheckH2DowngradeRequiresNegotiatedH2(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()

	h2 := &h2StateConn{Conn: raw, state: tls.ConnectionState{NegotiatedProtocol: "h2", HandshakeComplete: true}}
	if err := checkH2Downgrade(h2); err != nil {
		t.Fatalf("h2 connection rejected: %v", err)
	}

	plain := &h2StateConn{Conn: raw, state: tls.ConnectionState{NegotiatedProtocol: "http/1.1"}}
	if err := checkH2Downgrade(plain); !errors.Is(err, ErrNoH2ALPN) {
		t.Fatalf("http/1.1 error = %v, want ErrNoH2ALPN", err)
	}
	if err := checkH2Downgrade(raw); !errors.Is(err, ErrNoH2ALPN) {
		t.Fatalf("non-TLS error = %v, want ErrNoH2ALPN", err)
	}
}
