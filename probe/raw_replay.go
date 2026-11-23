package probe

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// RawReplayProbe sends a prebuilt raw payload (Universal Key) as-is.
type RawReplayProbe struct {
	RawPayloadB64   string
	RawPayloadHex   string
	SuccessContains string
	Timeout         time.Duration
	MaxHeader       int64
	MaxBody         int64
}

func (p *RawReplayProbe) Name() string { return "raw-replay" }

func (p *RawReplayProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	payload, err := p.payload()
	if err != nil {
		return nil, err
	}
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	defer e.finish()
	if err := e.write(payload); err != nil {
		return e.finish(), err
	}
	resp, err := e.read()
	if err != nil && !isTimeout(err) {
		return e.finish(), err
	}
	if p.SuccessContains != "" && resp != nil {
		marker := strings.ToLower(p.SuccessContains)
		if strings.Contains(strings.ToLower(resp.Body), marker) || strings.Contains(strings.ToLower(resp.Reason), marker) {
			e.addFinding(Finding{Kind: "universal_key_confirmed", Confidence: ConfidenceHigh, Detail: fmt.Sprintf("marker %q observed", p.SuccessContains), Response: resp.Seq})
			return e.finish(), nil
		}
	}
	e.addFinding(Finding{Kind: "raw_replay_unconfirmed", Confidence: ConfidenceLow, Detail: "raw payload sent; no confirmation marker"})
	return e.finish(), nil
}

func (p *RawReplayProbe) payload() ([]byte, error) {
	if s := strings.TrimSpace(p.RawPayloadB64); s != "" {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(s)
		}
		if err != nil {
			return nil, fmt.Errorf("probe: invalid raw_payload_b64: %w", err)
		}
		return b, nil
	}
	if s := strings.TrimSpace(p.RawPayloadHex); s != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return nil, fmt.Errorf("probe: invalid raw_payload_hex: %w", err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("probe: raw-replay requires raw_payload_b64 or raw_payload_hex")
}
