package daemon

import (
	"errors"
	"strings"

	"github.com/skyrimdlyalohov-droid/omnislash"
	"github.com/skyrimdlyalohov-droid/omnislash/probe"
)

// OutcomeLabel separates transport failures from responses that actually came
// from a target. Only target responses may become training evidence: a proxy
// that failed to connect says nothing about the technique under test.
type OutcomeLabel string

const (
	OutcomeProxyFailed    OutcomeLabel = "Proxy Failed"
	OutcomeWAFBlocked     OutcomeLabel = "WAF Blocked"
	OutcomeTargetRejected OutcomeLabel = "Target Rejected"
	OutcomeTargetResponse OutcomeLabel = "Target Response"
	// OutcomeEngineFault is a local correctness failure: a recovered panic or
	// a mandatory deception check that could not run. It is never a target
	// verdict and is never trainable.
	OutcomeEngineFault OutcomeLabel = "Engine Fault"
)

var outcomeLabels = map[string]OutcomeLabel{
	"proxy failed":    OutcomeProxyFailed,
	"proxy-failed":    OutcomeProxyFailed,
	"proxy_failed":    OutcomeProxyFailed,
	"waf blocked":     OutcomeWAFBlocked,
	"waf-blocked":     OutcomeWAFBlocked,
	"waf_blocked":     OutcomeWAFBlocked,
	"target rejected": OutcomeTargetRejected,
	"target-rejected": OutcomeTargetRejected,
	"target_rejected": OutcomeTargetRejected,
	"target response": OutcomeTargetResponse,
	"target-response": OutcomeTargetResponse,
	"target_response": OutcomeTargetResponse,
	"engine fault":    OutcomeEngineFault,
	"engine-fault":    OutcomeEngineFault,
	"engine_fault":    OutcomeEngineFault,
}

// ParseOutcomeLabel accepts the canonical label or its slug from an audit line.
func ParseOutcomeLabel(value string) (OutcomeLabel, bool) {
	label, ok := outcomeLabels[strings.ToLower(strings.TrimSpace(value))]
	return label, ok
}

// Trainable reports whether this outcome is a real target response. Proxy
// failures and engine faults are excluded absolutely; WAF/rejection responses
// are weak negative evidence, never positive proof.
func (l OutcomeLabel) Trainable() bool {
	switch l {
	case OutcomeWAFBlocked, OutcomeTargetRejected, OutcomeTargetResponse:
		return true
	default:
		return false
	}
}

var wafServers = []string{
	"cloudflare", "akamai", "imperva", "incapsula", "sucuri",
	"fortiweb", "mod_security", "modsecurity", "barracuda",
}

var wafBodyMarkers = []string{
	"captcha", "access denied", "request blocked", "blocked by",
	"bot detection", "security check", "waf", "web application firewall",
	"you have been blocked", "forbidden by",
}

var rejectBodyMarkers = []string{
	"invalid request", "bad request", "malformed", "not found",
	"method not allowed", "unsupported content-length", "parser reject",
}

// classifyOutcome labels one attempt. A result without any parsed response is
// a proxy/transport failure even when an error string is absent: there is no
// target response to learn from, only an absent observation.
func classifyOutcome(res *probe.Result, err error) OutcomeLabel {
	// A recovered panic or a mandatory semantic failure is an engine fault,
	// even if a partial response was parsed before the fault. It must never
	// become WAF or target evidence.
	if errors.Is(err, omnislash.ErrPrecisionLost) || errors.Is(err, omnislash.ErrDeceptionUncertain) {
		return OutcomeEngineFault
	}
	// EOF, resets, CONNECT failures and timeouts happened before the target
	// answered. They are proxy failures even if a caller attached a partial
	// result, and must stay out of the learning path.
	if omnislash.IsProxyTransportError(err) {
		return OutcomeProxyFailed
	}
	if res == nil || len(res.Responses) == 0 {
		return OutcomeProxyFailed
	}
	for _, r := range res.Responses {
		if wafBlocked(r) {
			return OutcomeWAFBlocked
		}
	}
	last := res.Responses[len(res.Responses)-1]
	if targetRejected(last) {
		return OutcomeTargetRejected
	}
	return OutcomeTargetResponse
}

func wafBlocked(r probe.Response) bool {
	if r.Status != 403 && r.Status != 429 && r.Status != 503 && r.Status != 406 {
		return false
	}
	body := strings.ToLower(r.Body)
	for _, marker := range wafBodyMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	for _, h := range r.Headers {
		key := strings.ToLower(h.Key)
		value := strings.ToLower(h.Value)
		if key == "cf-ray" || key == "x-sucuri-id" || key == "x-waf-event-id" {
			return true
		}
		if key != "server" && key != "x-powered-by" && key != "via" {
			continue
		}
		for _, marker := range wafServers {
			if strings.Contains(value, marker) {
				return true
			}
		}
	}
	// A bare 429 is a rate-limit block even without a vendor signature.
	return r.Status == 429 && strings.TrimSpace(r.Body) == ""
}

func targetRejected(r probe.Response) bool {
	switch r.Status {
	case 400, 404, 405, 411, 413, 414, 431, 501:
		return true
	}
	body := strings.ToLower(r.Body)
	for _, marker := range rejectBodyMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}
