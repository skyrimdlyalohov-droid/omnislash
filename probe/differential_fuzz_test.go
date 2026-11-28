package probe

import (
	"math"
	"strings"
	"testing"
)

func TestResponseStructuralShiftSuppressesDynamicTokens(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		base        string
		sample      string
		wantOK      bool
		wantShift   bool
	}{
		{
			name:        "json token and timestamp rotate",
			contentType: "application/json",
			base:        `{"admin_panel":true,"token":"AAAAAAAA","ts":1710000000,"items":[{"name":"a"}]}`,
			sample:      `{"admin_panel":true,"token":"BBBBBBBB","ts":1719999999,"items":[{"name":"a"}]}`,
			wantOK:      true,
			wantShift:   false,
		},
		{
			name:        "json gains a key",
			contentType: "application/json",
			base:        `{"admin_panel":true,"token":"AAAAAAAA","items":[{"name":"a"}]}`,
			sample:      `{"admin_panel":true,"token":"BBBBBBBB","secret":"new","items":[{"name":"a"}]}`,
			wantOK:      true,
			wantShift:   true,
		},
		{
			name:        "html csrf rotates",
			contentType: "text/html",
			base:        `<html><body><form><input name="csrf" value="AAAAAAAA"></form></body></html>`,
			sample:      `<html><body><form><input name="csrf" value="BBBBBBBB"></form></body></html>`,
			wantOK:      true,
			wantShift:   false,
		},
		{
			name:        "plain text has no skeleton",
			contentType: "text/plain",
			base:        `request 1710000000 accepted`,
			sample:      `request 1719999999 accepted`,
			wantOK:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &Response{
				Body:    tc.sample,
				Headers: []Header{{Key: "Content-Type", Value: tc.contentType}},
			}
			distance, ok := responseStructuralShift([]byte(tc.base), tc.contentType, resp)
			if ok != tc.wantOK {
				t.Fatalf("structural comparator available = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			shifted := distance > 0.15
			if shifted != tc.wantShift {
				t.Fatalf("distance = %.3f, shifted = %v, want %v", distance, shifted, tc.wantShift)
			}
		})
	}
}

func TestObserveSignedKeepsNegativeResiduals(t *testing.T) {
	var signed, latency Welford
	signed.ObserveSigned(-2.5)
	latency.Observe(-2.5)

	if signed.Count() != 1 {
		t.Fatalf("signed count = %d, want 1", signed.Count())
	}
	if math.Abs(signed.Mean()+2.5) > 1e-9 {
		t.Fatalf("signed mean = %v, want -2.5", signed.Mean())
	}
	if latency.Count() != 0 {
		t.Fatalf("latency count = %d, want 0", latency.Count())
	}
}

func TestTimingDesyncFindingUsesSignedResiduals(t *testing.T) {
	var clean, mutated Welford
	for i := 0; i < 6; i++ {
		clean.ObserveSigned(float64(i%3-1) * 0.1)
		mutated.ObserveSigned(-4 - float64(i)*0.1)
	}

	z, detail, ok := timingDesyncFinding(&clean, &mutated)
	if !ok {
		t.Fatal("timing finding was not produced")
	}
	if math.Abs(z) < SignalZThreshold {
		t.Fatalf("z = %.3f, want |z| >= %.1f", z, SignalZThreshold)
	}
	if !strings.Contains(detail, "z=") {
		t.Fatalf("detail = %q, want a z score", detail)
	}

	var empty Welford
	if _, _, ok := timingDesyncFinding(&empty, &mutated); ok {
		t.Fatal("an empty clean side must not produce timing evidence")
	}
}
