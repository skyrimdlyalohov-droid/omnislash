package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	rawhttp "github.com/projectdiscovery/rawhttp/client"
)

// Mutation describes a grammar mutation applied to an HTTP request.
type Mutation struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Mutator generates HTTP grammar mutations bound to a tech stack signature.
type Mutator struct {
	TechStack []string
	Seed      int64
}

// TechStackHash returns a stable hash for a tech stack.
func TechStackHash(stack []string) string {
	norm := make([]string, 0, len(stack))
	for _, s := range stack {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			norm = append(norm, s)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "|")))
	return hex.EncodeToString(sum[:8])
}

func (m Mutator) Hash() string { return TechStackHash(m.TechStack) }

// Mutations returns the available grammar mutations.
func (m Mutator) Mutations() []Mutation {
	return []Mutation{
		{Name: "ctl_nul", Category: "control", Description: "inject 0x00 in header value"},
		{Name: "ctl_tab", Category: "control", Description: "inject 0x09 in header value"},
		{Name: "ctl_vtab", Category: "control", Description: "inject 0x0b in header value"},
		{Name: "ctl_ff", Category: "control", Description: "inject 0x0c in header value"},
		{Name: "ctl_del", Category: "control", Description: "inject 0x7f in header value"},
		{Name: "unpaired_cr", Category: "linebreak", Description: "unpaired \\r in header folding"},
		{Name: "unpaired_lf", Category: "linebreak", Description: "unpaired \\n in header folding"},
		{Name: "space_before_colon", Category: "separator", Description: "Header : value"},
		{Name: "cl_te_duplicate", Category: "framing", Description: "duplicate CL and TE variations"},
		{Name: "te_obfuscation", Category: "framing", Description: "Transfer-Encoding obfuscation"},
	}
}

// Apply applies a named mutation to a base request and returns raw bytes.
func (m Mutator) Apply(name string, target Target) ([]byte, Mutation, error) {
	basePath := target.RequestPath()
	if !strings.Contains(basePath, "_omni_cb=") {
		basePath = AppendCacheBuster(basePath)
	}
	spec := requestSpec{
		Method:  "GET",
		Path:    basePath,
		Version: rawhttp.HTTP_1_1,
		Headers: []rawhttp.Header{
			{Key: "Host", Value: target.HostHeader()},
			{Key: "User-Agent", Value: "omnislash-probe/1"},
			{Key: "Accept", Value: "*/*"},
			{Key: "Connection", Value: "keep-alive"},
		},
	}
	mut := Mutation{Name: name, Category: "unknown"}

	switch name {
	case "ctl_nul", "ctl_tab", "ctl_vtab", "ctl_ff", "ctl_del":
		b := map[string]byte{"ctl_nul": 0x00, "ctl_tab": 0x09, "ctl_vtab": 0x0b, "ctl_ff": 0x0c, "ctl_del": 0x7f}[name]
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value" + string([]byte{b}) + "x"})
		mut = Mutation{Name: name, Category: "control", Description: "control byte in header value"}
	case "unpaired_cr":
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value\rinjected"})
		mut = Mutation{Name: name, Category: "linebreak", Description: "unpaired CR"}
	case "unpaired_lf":
		spec.Headers = append(spec.Headers, rawhttp.Header{Key: "X-Omni-Probe", Value: "value\ninjected"})
		mut = Mutation{Name: name, Category: "linebreak", Description: "unpaired LF"}
	case "space_before_colon":
		// Render manually to preserve "Header : value"
		mut = Mutation{Name: name, Category: "separator", Description: "space before colon"}
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent : omnislash-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", spec.Path, target.HostHeader())
		return []byte(raw), mut, nil
	case "cl_te_duplicate":
		mut = Mutation{Name: name, Category: "framing", Description: "CL/TE duplicate"}
		body := "0\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\n\r\n%s", spec.Path, target.HostHeader(), body)
		return []byte(raw), mut, nil
	case "te_obfuscation":
		mut = Mutation{Name: name, Category: "framing", Description: "TE obfuscation"}
		body := "0\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\nConnection: keep-alive\r\n\r\n%s", spec.Path, target.HostHeader(), body)
		return []byte(raw), mut, nil
	default:
		return nil, mut, fmt.Errorf("unknown mutation %q", name)
	}

	b, err := render(spec)
	if err != nil {
		// fallback: build manually for control chars that rawhttp may normalize
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: omnislash-probe/1\r\nX-Omni-Probe: value%sx\r\nAccept: */*\r\nConnection: close\r\n\r\n", spec.Path, target.HostHeader(), mutationControl(name))
		return []byte(raw), mut, nil
	}
	return b, mut, nil
}

func mutationControl(name string) string {
	switch name {
	case "ctl_nul":
		return "\x00"
	case "ctl_tab":
		return "\x09"
	case "ctl_vtab":
		return "\x0b"
	case "ctl_ff":
		return "\x0c"
	case "ctl_del":
		return "\x7f"
	default:
		return ""
	}
}

// ApplyRandom picks a mutation (deterministic by seed/index if caller controls it).
func (m Mutator) ApplyRandom(target Target, idx int) ([]byte, Mutation, error) {
	muts := m.Mutations()
	if len(muts) == 0 {
		return nil, Mutation{}, fmt.Errorf("no mutations")
	}
	i := idx % len(muts)
	if i < 0 {
		i = -i
	}
	return m.Apply(muts[i].Name, target)
}
