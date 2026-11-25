package daemon

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// LearningMeta is the small, stable part of an attempt that can be used as a
// training signal. The full evidence stays in Record.Result; this is only the
// label the experience store aggregates on.
type LearningMeta struct {
	Host      string `json:"host,omitempty"`
	Variant   string `json:"variant,omitempty"`
	Mutation  string `json:"mutation,omitempty"`
	TechStack string `json:"tech_stack,omitempty"`
	Finding   string `json:"finding,omitempty"`
}

// ExperienceKey identifies one configuration cell: the same host, transport,
// probe family and mutation/variant. Experience is never generalized across
// hosts — a technique that worked on one lab must earn its prior on another.
type ExperienceKey struct {
	Host      string
	TLS       string
	Probe     string
	Variant   string
	Mutation  string
	TechStack string
}

func (k ExperienceKey) id() string {
	return strings.ToLower(strings.Join([]string{k.Host, k.TLS, k.Probe, k.Variant, k.Mutation, k.TechStack}, "|"))
}

// ExperienceStat is one learned cell. Attempts and Successes come from real
// audit records. SeedAttempts and SeedSuccesses come from curated playbooks
// and are kept separate so a prior is never presented as observed evidence.
type ExperienceStat struct {
	Key           ExperienceKey `json:"key"`
	Attempts      int           `json:"attempts"`
	Successes     int           `json:"successes"`
	SeedAttempts  int           `json:"seed_attempts,omitempty"`
	SeedSuccesses int           `json:"seed_successes,omitempty"`
	SeedSources   []string      `json:"seed_sources,omitempty"`
	LastSuccess   time.Time     `json:"last_success,omitempty"`
	// Outcome counters keep the three failure classes separate. Proxy failures
	// never contribute to Attempts: the target was never reached.
	ProxyFailures   int `json:"proxy_failures,omitempty"`
	WAFBlocks       int `json:"waf_blocks,omitempty"`
	TargetRejects   int `json:"target_rejects,omitempty"`
	TargetResponses int `json:"target_responses,omitempty"`
}

// Score is a Laplace-smoothed success probability. Curated seeds are counted,
// but remain visible in Summary under seed_* fields. The prior of 0.5 keeps an
// untried candidate from being permanently ranked last and avoids divide-by-zero.
func (s ExperienceStat) Score() float64 {
	return float64(s.Successes+s.SeedSuccesses+1) / float64(s.Attempts+s.SeedAttempts+2)
}

// ExperienceSeed is a curated prior, not an audit record. Host "*" seeds only
// the host-independent cell; any other host seeds both the exact cell and the
// global cell. Provenance and Source are exposed by /experience so callers can
// tell a solution-derived playbook from an empirical observation.
type ExperienceSeed struct {
	Host       string `json:"host,omitempty"`
	TLS        string `json:"tls,omitempty"`
	Probe      string `json:"probe,omitempty"`
	Variant    string `json:"variant,omitempty"`
	Mutation   string `json:"mutation,omitempty"`
	TechStack  string `json:"tech_stack,omitempty"`
	Attempts   int    `json:"attempts"`
	Successes  int    `json:"successes"`
	Provenance string `json:"provenance,omitempty"`
	Source     string `json:"source,omitempty"`
}

// ExperienceStore reads the daemon's JSONL audit log back into a compact
// success/failure table and ranks candidate variants or mutations with it.
// It is deliberately not a model: every verdict still comes from a probe's
// raw exchange, and the learned value is only an ordering prior.
type ExperienceStore struct {
	mu    sync.Mutex
	path  string
	stats map[string]*ExperienceStat
}

// NewExperienceStore creates a store. When path is empty the store works in
// memory only; when the file does not exist it starts empty.
func NewExperienceStore(path string) *ExperienceStore {
	return &ExperienceStore{path: path, stats: make(map[string]*ExperienceStat)}
}

// Load rebuilds the table from previous audit lines. A damaged line is skipped
// rather than aborting the daemon: the audit log is evidence, not a database.
func (s *ExperienceStore) Load() error {
	return s.loadPath(s.path)
}

// LoadFiles replays additional audit logs into the same experience table.
func (s *ExperienceStore) LoadFiles(paths []string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if err := s.loadPath(p); err != nil {
			return err
		}
	}
	return nil
}

func (s *ExperienceStore) loadPath(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		s.observe(rec)
	}
	return sc.Err()
}

// Observe folds one audit record into the table.
func (s *ExperienceStore) Observe(rec Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observe(rec)
}

// Seed folds curated playbook priors into the table. It never creates a fake
// Record, so audit logs and /experience remain honest about what was observed.
func (s *ExperienceStore) Seed(seeds []ExperienceSeed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seed := range seeds {
		if seed.Attempts <= 0 {
			continue
		}
		successes := seed.Successes
		if successes < 0 {
			successes = 0
		}
		if successes > seed.Attempts {
			successes = seed.Attempts
		}
		key := ExperienceKey{
			Host:      seed.Host,
			TLS:       seed.TLS,
			Probe:     seed.Probe,
			Variant:   seed.Variant,
			Mutation:  seed.Mutation,
			TechStack: seed.TechStack,
		}
		if key.Host == "" || key.Host == "*" {
			key.Host = "*"
			s.addSeed(key, seed.Attempts, successes, seed)
			continue
		}
		s.addSeed(key, seed.Attempts, successes, seed)
		s.addSeed(globalKey(key), seed.Attempts, successes, seed)
	}
}

func (s *ExperienceStore) addSeed(key ExperienceKey, attempts, successes int, seed ExperienceSeed) {
	id := key.id()
	st, ok := s.stats[id]
	if !ok {
		st = &ExperienceStat{Key: key}
		s.stats[id] = st
	}
	st.SeedAttempts += attempts
	st.SeedSuccesses += successes
	label := seed.Provenance
	if seed.Source != "" {
		if label == "" {
			label = seed.Source
		} else {
			label += ":" + seed.Source
		}
	}
	if label != "" {
		for _, existing := range st.SeedSources {
			if existing == label {
				return
			}
		}
		st.SeedSources = append(st.SeedSources, label)
	}
}

func (s *ExperienceStore) observe(rec Record) {
	label := outcomeOf(rec)
	key := keyFromRecord(rec)
	// A dead proxy is not negative evidence against a probe variant: it is
	// counted in its own class and never enters Attempts. A second,
	// host-independent cell lets techniques proven on previous labs seed the
	// prior for a fresh instance of the same technique.
	s.observeKey(key, label, rec.Success, rec.Time)
	s.observeKey(globalKey(key), label, rec.Success, rec.Time)
}

func outcomeOf(rec Record) OutcomeLabel {
	if label, ok := ParseOutcomeLabel(rec.Outcome); ok {
		return label
	}
	if rec.Result == nil {
		if rec.Error != "" {
			return OutcomeProxyFailed
		}
		// Legacy in-memory/playbook records carry no result bytes. They are
		// retained as target responses so old audit logs stay readable, while
		// new records always carry an explicit outcome label.
		return OutcomeTargetResponse
	}
	return classifyOutcome(rec.Result, nil)
}

func (s *ExperienceStore) observeKey(key ExperienceKey, label OutcomeLabel, success bool, when time.Time) {
	id := key.id()
	st, ok := s.stats[id]
	if !ok {
		st = &ExperienceStat{Key: key}
		s.stats[id] = st
	}
	switch label {
	case OutcomeProxyFailed:
		st.ProxyFailures++
		return
	case OutcomeWAFBlocked:
		st.WAFBlocks++
	case OutcomeTargetRejected:
		st.TargetRejects++
	case OutcomeTargetResponse:
		st.TargetResponses++
	}
	st.Attempts++
	// Only a genuine target response can turn into a success. A WAF page or a
	// parser rejection is negative evidence at best, never proof of a finding.
	if success && label == OutcomeTargetResponse {
		st.Successes++
		st.LastSuccess = when
	}
}

func globalKey(k ExperienceKey) ExperienceKey {
	k.Host = "*"
	return k
}

func (s *ExperienceStore) statFor(k ExperienceKey) (ExperienceStat, bool) {
	if st, ok := s.stats[k.id()]; ok {
		return *st, true
	}
	if st, ok := s.stats[globalKey(k).id()]; ok {
		return *st, true
	}
	return ExperienceStat{}, false
}

// Rank returns candidates ordered by learned success probability, highest
// first. Equal scores keep the caller's order, so learning never introduces
// nondeterminism.
func (s *ExperienceStore) Rank(base ExperienceKey, candidates []string) []string {
	if len(candidates) < 2 {
		return append([]string(nil), candidates...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ranked := make([]string, len(candidates))
	copy(ranked, candidates)
	scores := make(map[string]float64, len(candidates))
	for _, c := range ranked {
		k := base
		k.Variant = c
		if st, ok := s.statFor(k); ok {
			scores[c] = st.Score()
		} else {
			scores[c] = 0.5
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return scores[ranked[i]] > scores[ranked[j]] })
	return ranked
}

// RankMutations is Rank for the mutation dimension of an ExperienceKey.
func (s *ExperienceStore) RankMutations(base ExperienceKey, candidates []string) []string {
	if len(candidates) < 2 {
		return append([]string(nil), candidates...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ranked := make([]string, len(candidates))
	copy(ranked, candidates)
	scores := make(map[string]float64, len(candidates))
	for _, c := range ranked {
		k := base
		k.Mutation = c
		if st, ok := s.statFor(k); ok {
			scores[c] = st.Score()
		} else {
			scores[c] = 0.5
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return scores[ranked[i]] > scores[ranked[j]] })
	return ranked
}

// Summary returns a stable snapshot for the /experience control endpoint.
func (s *ExperienceStore) Summary() []ExperienceStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ExperienceStat, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.id() == out[j].Key.id() {
			return out[i].Attempts > out[j].Attempts
		}
		return out[i].Key.id() < out[j].Key.id()
	})
	return out
}

func keyFromRecord(rec Record) ExperienceKey {
	host := rec.Learning.Host
	if host == "" {
		host = hostFromAddr(rec.Target)
	}
	return ExperienceKey{
		Host:      host,
		TLS:       rec.TLS,
		Probe:     rec.Probe,
		Variant:   rec.Learning.Variant,
		Mutation:  rec.Learning.Mutation,
		TechStack: rec.Learning.TechStack,
	}
}

func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
