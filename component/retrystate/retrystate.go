package retrystate

import (
	"context"
	"sync"
)

// State is mutable state owned by one official retry loop. tunnel.retry
// creates it once, so every attempt of one connection shares the same state
// while another connection never does. The state is deliberately opaque:
// callers store their own typed session in the single value slot.
type State struct {
	mu     sync.Mutex
	value  any
	finish []func()
	done   bool
}

type contextKey struct{}

// WithState attaches a fresh retry state to ctx. The second return value is
// the same state, so the retry loop can finish it without a second lookup.
func WithState(ctx context.Context) (context.Context, *State) {
	state := &State{}
	return context.WithValue(ctx, contextKey{}, state), state
}

// From returns the retry state attached by tunnel.retry. Direct dial callers
// that never enter the official loop get ok=false and must not share state.
func From(ctx context.Context) (*State, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(contextKey{}).(*State)
	return state, ok
}

// Value returns the state's single value, creating it with init on first use.
// One retry loop serves one connection, so one slot is enough; a map would
// let unrelated strategies collide.
func (s *State) Value(init func() any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value == nil {
		s.value = init()
	}
	return s.value
}

// OnFinish registers cleanup owned by the retry scope. If the loop has
// already finished, fn runs immediately.
func (s *State) OnFinish(fn func()) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		fn()
		return
	}
	s.finish = append(s.finish, fn)
	s.mu.Unlock()
}

// Finish runs retry-scope cleanup once. It is deferred by tunnel.retry, not by
// the connection: a successful connection keeps its own handle reference after
// this returns.
func (s *State) Finish() {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	finish := s.finish
	s.finish = nil
	s.mu.Unlock()

	for i := len(finish) - 1; i >= 0; i-- {
		finish[i]()
	}
}
