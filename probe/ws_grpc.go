package probe

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// UpgradeDesyncProbe tests WebSocket upgrade desync and gRPC/H2C upgrade boundary issues.
type UpgradeDesyncProbe struct {
	// UpgradeType: "websocket", "grpc", "h2c", or "auto"
	UpgradeType     string
	Path            string
	SuccessContains string
	Timeout         time.Duration
	MaxHeader       int64
	MaxBody         int64
}

func (p *UpgradeDesyncProbe) Name() string { return "upgrade-desync" }

func (p *UpgradeDesyncProbe) Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error) {
	e := newExec(ctx, p.Name(), target, conn, p.Timeout, p.MaxHeader, p.MaxBody)
	defer e.finish()
	ut := strings.ToLower(strings.TrimSpace(p.UpgradeType))
	if ut == "" || ut == "auto" {
		ut = "websocket"
	}
	var payload []byte
	var err error
	switch ut {
	case "websocket":
		payload, err = p.buildWebSocketUpgrade(target)
	case "grpc", "h2c":
		payload, err = p.buildH2CUpgrade(target)
	default:
		return e.finish(), fmt.Errorf("probe: unsupported upgrade_type %q", p.UpgradeType)
	}
	if err != nil {
		return e.finish(), err
	}

	if err := e.write(payload); err != nil {
		return e.finish(), err
	}
	resp, err := e.read()
	if err != nil && !isTimeout(err) {
		return e.finish(), err
	}
	if resp != nil {
		p.analyzeUpgradeResponse(e, ut, resp)
	}

	// Follow-up probe: send a smuggled raw HTTP request after upgrade attempt to detect tunnel/desync.
	smuggle := fmt.Sprintf("GET /__omni_upgrade_probe__ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.HostHeader())
	_ = e.write([]byte(smuggle))
	resp2, _ := e.read()
	if resp2 != nil {
		if p.SuccessContains != "" && strings.Contains(strings.ToLower(resp2.Body), strings.ToLower(p.SuccessContains)) {
			e.addFinding(Finding{Kind: "upgrade_desync_confirmed", Confidence: ConfidenceHigh, Detail: "marker observed after upgrade follow-up", Response: resp2.Seq})
		}
	}
	if len(e.res.Findings) == 0 {
		e.addFinding(Finding{Kind: "upgrade_desync_unconfirmed", Confidence: ConfidenceLow, Detail: fmt.Sprintf("%s upgrade probe completed without confirmation", ut)})
	}
	return e.finish(), nil
}

func (p *UpgradeDesyncProbe) buildWebSocketUpgrade(target Target) ([]byte, error) {
	path := p.Path
	if path == "" {
		path = target.RequestPath()
	}
	key, err := wsKey()
	if err != nil {
		return nil, err
	}
	// Deliberate boundary probe: Upgrade headers with Content-Length mismatch/ambiguity
	// for reverse-proxy/backend disagreement detection. Sent as raw bytes.
	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + target.HostHeader(),
		"User-Agent: omnislash-probe/1",
		"Connection: Upgrade",
		"Upgrade: websocket",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: " + key,
		"Content-Length: 0",
		"\r\n",
	}, "\r\n")
	return []byte(req), nil
}

func (p *UpgradeDesyncProbe) buildH2CUpgrade(target Target) ([]byte, error) {
	path := p.Path
	if path == "" {
		path = target.RequestPath()
	}
	// H2C/HTTP2-Settings upgrade probe (HTTP/1.1)
	settings := base64.RawURLEncoding.EncodeToString([]byte{0})
	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + target.HostHeader(),
		"User-Agent: omnislash-probe/1",
		"Connection: Upgrade, HTTP2-Settings",
		"Upgrade: h2c",
		"HTTP2-Settings: " + settings,
		"\r\n",
	}, "\r\n")
	return []byte(req), nil
}

func (p *UpgradeDesyncProbe) analyzeUpgradeResponse(e *exec, ut string, resp *Response) {
	status := resp.Status
	if ut == "websocket" && status == 101 {
		e.addFinding(Finding{Kind: "upgrade_101_observed", Confidence: ConfidenceMedium, Detail: "WebSocket 101 Switching Protocols observed; boundary requires manual verification", Response: resp.Seq})
	}
	if (ut == "grpc" || ut == "h2c") && (status == 101 || status == 200) {
		e.addFinding(Finding{Kind: "h2c_upgrade_observed", Confidence: ConfidenceMedium, Detail: fmt.Sprintf("H2C upgrade response status=%d observed", status), Response: resp.Seq})
	}
	if status == 400 || status == 502 || status == 503 {
		e.addFinding(Finding{Kind: "upgrade_boundary_anomaly", Confidence: ConfidenceLow, Detail: fmt.Sprintf("upgrade probe returned status=%d", status), Response: resp.Seq})
	}
}

func wsKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}
