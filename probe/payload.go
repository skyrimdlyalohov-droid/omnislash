package probe

import (
	"context"
	"sync"
)

// payloadSink remembers the most recent bytes handed to the socket. If a probe
// panics while processing a response, Runner can attach the exact request
// payload to the panic audit instead of logging an empty stack-only record.
type payloadSink struct {
	mu   sync.Mutex
	last []byte
}

type payloadSinkKey struct{}

func withPayloadSink(ctx context.Context, sink *payloadSink) context.Context {
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, payloadSinkKey{}, sink)
}

func payloadSinkFrom(ctx context.Context) *payloadSink {
	if ctx == nil {
		return nil
	}
	sink, _ := ctx.Value(payloadSinkKey{}).(*payloadSink)
	return sink
}

func (s *payloadSink) record(payload []byte) {
	if s == nil || len(payload) == 0 {
		return
	}
	s.mu.Lock()
	s.last = append(s.last[:0], payload...)
	s.mu.Unlock()
}

func (s *payloadSink) snapshot() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.last...)
}
