//go:build linux

package omnislash

import (
	"syscall"
)

// tuneDialSocket applies kernel-level acceleration that is safe for every
// proxy-backed request: no Nagle delay, keepalive detection, and immediate ACK
// for interactive request/response streams. Errors are ignored by net.Dialer's
// Control hook so an unusual kernel cannot break dialling itself.
func tuneDialSocket(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	})
	return nil
}
