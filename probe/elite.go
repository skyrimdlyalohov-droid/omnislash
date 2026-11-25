package probe

// ElitePool keeps the two highest-fitness raw request patterns. It is a
// bounded, O(1)-memory pool owned by the orchestrator: the mutator only reads
// a copy of its patterns and never schedules work on its own.
type ElitePool struct {
	first  elitePattern
	second elitePattern
}

type elitePattern struct {
	payload []byte
	fitness float64
}

const maxElitePayload = 8 << 10

// Add promotes a confirmed mutation into the elite pool. Low-fitness patterns
// are ignored; payloads are copied and capped so a hostile response cannot
// grow the pool without bound.
func (p *ElitePool) Add(payload []byte, fitness float64) bool {
	if p == nil || len(payload) == 0 || fitness <= 0 {
		return false
	}
	if len(payload) > maxElitePayload {
		payload = payload[:maxElitePayload]
	}
	copyPayload := append([]byte(nil), payload...)
	candidate := elitePattern{payload: copyPayload, fitness: fitness}
	if candidate.fitness > p.first.fitness {
		p.second = p.first
		p.first = candidate
		return true
	}
	if candidate.fitness > p.second.fitness {
		p.second = candidate
		return true
	}
	return false
}

// Patterns returns copies of the confirmed patterns, highest fitness first.
func (p *ElitePool) Patterns() [][]byte {
	if p == nil {
		return nil
	}
	out := make([][]byte, 0, 2)
	for _, pattern := range []elitePattern{p.first, p.second} {
		if len(pattern.payload) > 0 {
			out = append(out, append([]byte(nil), pattern.payload...))
		}
	}
	return out
}

// BestFitness reports the strongest confirmed reward in the pool.
func (p *ElitePool) BestFitness() float64 {
	if p == nil {
		return 0
	}
	return p.first.fitness
}
