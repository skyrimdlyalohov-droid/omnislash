package omnislash

import (
	"testing"
)

func TestNormalizedCompressionDistanceRange(t *testing.T) {
	a := []byte("hello world this is a test payload")
	b := []byte("hello world this is a different payload")
	ncd := NormalizedCompressionDistance(a, b)
	if ncd < 0 || ncd > 1 {
		t.Fatalf("NCD out of range: %v", ncd)
	}
	if NormalizedCompressionDistance(nil, nil) != 0 {
		t.Fatal("expected 0 for empty inputs")
	}
}

func TestNormalizedCompressionDistanceSimilar(t *testing.T) {
	a := []byte(`<html><body><h1>Admin</h1><p>Token: abc123</p><script>var t="2026-01-01T00:00:00Z"</script></body></html>`)
	b := []byte(`<html><body><h1>Admin</h1><p>Token: xyz789</p><script>var t="2026-01-02T00:00:00Z"</script></body></html>`)
	ncd := NormalizedCompressionDistance(a, b)
	if ncd >= 0.25 {
		t.Fatalf("expected similar templates to have low NCD, got %v", ncd)
	}
}

func TestNormalizedCompressionDistanceDifferent(t *testing.T) {
	a := []byte(`{"status":"ok","service":"api","version":1}`)
	b := []byte(`<html><head><title>Totally different page with lots of markup and text</title></head><body><div class="container"><p>Paragraph one</p><p>Paragraph two</p></div></body></html>`)
	ncd := NormalizedCompressionDistance(a, b)
	if ncd <= 0.4 {
		t.Fatalf("expected different structures to have higher NCD, got %v", ncd)
	}
}

func TestIsDynamicTarpitTemplate(t *testing.T) {
	samples := [][]byte{
		[]byte(`<html><body>Welcome <span id="ts">1700000001</span> token=aaa111 endpoint=/api/a</body></html>`),
		[]byte(`<html><body>Welcome <span id="ts">1700000002</span> token=bbb222 endpoint=/api/a</body></html>`),
		[]byte(`<html><body>Welcome <span id="ts">1700000003</span> token=ccc333 endpoint=/api/a</body></html>`),
	}
	if !IsDynamicTarpitTemplate(samples, 0.25) {
		t.Fatalf("expected dynamic tarpit template detected")
	}
	different := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`<html>completely different</html>`),
		[]byte(`plain text response`),
	}
	if IsDynamicTarpitTemplate(different, 0.25) {
		t.Fatalf("expected different samples not flagged as dynamic tarpit")
	}
}

func TestIsStructuralAnomaly(t *testing.T) {
	baseline := []byte(`{"error":"not found","code":404,"message":"resource missing","path":"/api/v1/users/123"}`)
	normal := []byte(`{"error":"not found","code":404,"message":"resource missing","path":"/api/v1/users/456"}`)
	anomaly := []byte(`<html><body><h1>Admin Panel</h1><form><input name="token" value="secret"/></form><table><tr><td>user</td><td>pass</td></tr></table></body></html>`)
	if IsStructuralAnomaly(baseline, normal, 0.6) {
		t.Fatalf("small variation should not be structural anomaly")
	}
	if !IsStructuralAnomaly(baseline, anomaly, 0.6) {
		t.Fatalf("large structural change should be anomaly")
	}
}
