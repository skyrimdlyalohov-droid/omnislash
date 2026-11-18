package omnislash

import "errors"

var (
	// ErrNoProxyAvailable is returned when every proxy is disabled, cooling
	// down, or excluded from the current attempt.
	ErrNoProxyAvailable = errors.New("omnislash: no proxy available")

	// ErrPoolClosed is returned after Pool.Close.
	ErrPoolClosed = errors.New("omnislash: pool is closed")

	// ErrNoProxies is returned by NewPool when no proxies were supplied and
	// direct connections are disabled.
	ErrNoProxies = errors.New("omnislash: proxy list is empty and allow_direct is false")

	// ErrSessionExpired is returned when a pinned experiment session is used
	// after its explicit lifetime. It never silently rotates to another exit IP.
	ErrSessionExpired = errors.New("omnislash: experiment session expired")

	// ErrSessionClosed is returned after Session.Close.
	ErrSessionClosed = errors.New("omnislash: experiment session closed")
)
