//go:build !linux

package omnislash

import (
	"syscall"
)

// tuneDialSocket keeps the portable subset of the socket tuning. TCP_QUICKACK
// is Linux-specific and intentionally absent here.
func tuneDialSocket(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	})
	return nil
}
