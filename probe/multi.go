package probe

import (
	"context"
	"errors"
	"net"
)

// ConnSource yields connections for one probe execution. Every connection it
// returns belongs to the same pinned session, so a multi-connection technique
// still runs on one exit IP.
//
// The source is created by Runner and backed by omnislash. A probe must never
// dial on its own: it can only ask this source for another socket.
type ConnSource interface {
	Dial(ctx context.Context) (net.Conn, error)
}

// MultiConnProbe is implemented by techniques that need more than one socket:
// for example a front-end that closes each client connection while reusing its
// back-end connection, so a desync planted on one socket is observed on the
// next. Omnislash still owns every socket; the probe only writes bytes.
type MultiConnProbe interface {
	Probe
	ExecuteMulti(ctx context.Context, target Target, source ConnSource) (*Result, error)
}

// ErrMultiConn reports that a probe needs several connections and cannot run
// on the single conn passed to Execute.
var ErrMultiConn = errors.New("probe: technique requires multiple connections")
