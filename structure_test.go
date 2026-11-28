package omnislash

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStructuralComparatorIgnoresDynamicValues(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		base        string
		sample      string
		wantSame    bool
	}{
		{
			name:        "html csrf timestamp and ad id",
			contentType: "text/html",
			base:        `<html><body><form><input name="csrf" value="CSRF_AAAAAAAA"></form><span>1710000000</span><div data-ad="AD_1"></div></body></html>`,
			sample:      `<html><body><form><input name="csrf" value="CSRF_BBBBBBBB"></form><span>1719999999</span><div data-ad="AD_2"></div></body></html>`,
			wantSame:    true,
		},
		{
			name:        "json token timestamp and ad id",
			contentType: "application/json",
			base:        `{"admin_panel":true,"token":"TOKEN_AAAAAAAA","ts":1710000000,"items":[{"ad_id":"AD_1","name":"a"}]}`,
			sample:      `{"admin_panel":true,"token":"TOKEN_BBBBBBBB","ts":1719999999,"items":[{"ad_id":"AD_2","name":"a"}]}`,
			wantSame:    true,
		},
		{
			name:        "html gains an element",
			contentType: "text/html",
			base:        `<html><body><form><input name="csrf" value="A"></form></body></html>`,
			sample:      `<html><body><form><input name="csrf" value="B"></form><table><tr><td>x</td></tr></table></body></html>`,
			wantSame:    false,
		},
		{
			name:        "json gains a key",
			contentType: "application/json",
			base:        `{"admin_panel":true,"token":"AAAAAAAAAA","items":[{"name":"a"}]}`,
			sample:      `{"admin_panel":true,"token":"BBBBBBBBBB","secret":"new","items":[{"name":"a"}]}`,
			wantSame:    false,
		},
		{
			name:        "plain text is not structurally tokenized",
			contentType: "text/plain",
			base:        `request 1710000000 accepted`,
			sample:      `request 1719999999 accepted`,
			wantSame:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := AnalyzeStructure([]byte(tc.base), tc.contentType)
			b := AnalyzeStructure([]byte(tc.sample), tc.contentType)
			if a.Skeleton == "" || a.Fingerprint == 0 {
				// text/plain has no structural tokens; that is a valid case.
				if a.Kind != "text" {
					t.Fatalf("no structural profile for %s: %+v", a.Kind, a)
				}
			}
			distance := StructuralDistance(a, b)
			if tc.wantSame && distance != 0 {
				t.Fatalf("dynamic values changed the skeleton: distance=%.3f\nbase=%s\nsample=%s", distance, a.Skeleton, b.Skeleton)
			}
			if !tc.wantSame && distance <= 0.15 {
				t.Fatalf("structural change was invisible: distance=%.3f\nbase=%s\nsample=%s", distance, a.Skeleton, b.Skeleton)
			}
			if again := AnalyzeStructure([]byte(tc.base), tc.contentType); again.Fingerprint != a.Fingerprint || again.Skeleton != a.Skeleton {
				t.Fatal("structural profile is not deterministic")
			}
			if shifted := StructuralShift([]byte(tc.base), []byte(tc.sample), tc.contentType); shifted != distance {
				t.Fatalf("StructuralShift = %.3f, want %.3f", shifted, distance)
			}
		})
	}
}

func TestLocalStructuralComparatorProtectsDeceptionBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"admin_panel":true,"token":"BASELINE_AAAAAAAA","items":[{"name":"a"}]}`)
	}))
	defer srv.Close()

	cfg := DeceptionConfig{
		Enabled:             true,
		BaselineSamples:     2,
		MaxBodySample:       64 << 10,
		SimilarityThreshold: 0.99,
		RepeatStatus:        200,
		RepeatThreshold:     100,
		NCDStructural:       0.15,
		NCDTarpit:           0.25,
		SemanticService:     false,
	}
	f := NewDeceptionFilter(cfg, nil)
	_, err := f.CalibrateBaseline(context.Background(), srv.URL, "/api", func(ctx context.Context, rawURL string) (*http.Response, time.Duration, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		resp, err := srv.Client().Do(req)
		return resp, time.Millisecond, err
	})
	if err != nil {
		t.Fatal(err)
	}
	base := f.baselines[baselineKey("127.0.0.1", "/api")]
	if base == nil || len(base.Structure.keys) == 0 {
		t.Fatal("local structural profile was not stored in the baseline")
	}

	rotated := []byte(`{"admin_panel":true,"token":"REAL_BBBBBBBB","items":[{"name":"a"}]}`)
	if d, _ := f.InspectResponseWithContentType("127.0.0.1", "/api/users", 200, rotated, "application/json", time.Millisecond); d.Flagged {
		t.Fatalf("rotated token was flagged as a structural shift: %+v", d)
	}

	shifted := []byte(`{"admin_panel":true,"token":"REAL_BBBBBBBB","secret":"new","items":[{"name":"a"}]}`)
	d, _ := f.InspectResponseWithContentType("127.0.0.1", "/api/users", 200, shifted, "application/json", time.Millisecond)
	if !d.Flagged || !strings.Contains(d.Reason, "local skeleton") {
		t.Fatalf("new JSON key was not flagged via the local skeleton: %+v", d)
	}
}
