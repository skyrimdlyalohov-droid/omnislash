package omnislash

import (
	"errors"

	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

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

	// ErrCircuitOpen is returned when the safety circuit breaker has stopped
	// traffic after repeated block responses or after the request budget was
	// exhausted.
	ErrCircuitOpen = errors.New("omnislash: safety circuit is open")

	// ErrPrecisionLost is returned when a local code fault (a recovered panic)
	// stopped a probe. It is never proxy or WAF evidence and is never trainable.
	ErrPrecisionLost = util.ErrPrecisionLost

	// ErrResponseTooLarge means the peer sent more bytes than the configured
	// response bound. The response is rejected, never silently truncated: a
	// truncated body would corrupt NCD and framing analysis.
	ErrResponseTooLarge = errors.New("omnislash: response exceeds configured byte limit")

	// ErrTimeout is a sentinel for a read deadline. The concrete error still
	// implements net.Error, so probes that treat a timeout as evidence keep
	// working.
	ErrTimeout = errors.New("omnislash: read timeout")

	// ErrDeceptionUncertain means the semantic/NCD check was mandatory and its
	// result could not be obtained. Failing closed is the only safe action:
	// raw bytes must not be treated as a clean response when a honeypot is
	// possible.
	ErrDeceptionUncertain = errors.New("omnislash: deception analysis uncertain")

	// ErrTargetCooling means the target produced a burst of block responses
	// across independent proxies and is paused. Other targets remain eligible.
	ErrTargetCooling = errors.New("omnislash: target cooling down")
)
