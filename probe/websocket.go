package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// WebSocketProbe is the WebSocket handshake module. It is part of the
// architecture but intentionally unimplemented: gorilla/websocket performs its
// own handshake on a connection it opens, so it cannot adopt a socket that
// omnislash already owns. Using it here would either open a second connection
// (a different exit IP) or duplicate the handshake.
//
// The compliant implementation is small and does not need a new dependency:
// render the upgrade request with rawhttp, write it, read the 101 response with
// the package reader, then parse frames (FIN/opcode/mask/length) directly. It is
// left out of this skeleton because frame parsing needs its own test fixtures
// and must handle masking, fragmentation and control frames carefully.
type WebSocketProbe struct {
	Path    string
	Origin  string
	Timeout time.Duration
}

func (p *WebSocketProbe) Name() string { return "websocket/handshake" }

// Execute returns ErrNotImplemented until the frame parser lands.
func (p *WebSocketProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, 0, 0)
	return e.finish(), fmt.Errorf("%w: websocket frame parsing is not implemented; see the type comment", ErrNotImplemented)
}
