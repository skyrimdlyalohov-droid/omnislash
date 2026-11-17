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
)
