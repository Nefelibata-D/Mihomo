package weightedsticky

import (
	"context"
	"sync"

	"github.com/metacubex/mihomo/component/retrystate"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// stopRetryError marks a result that cannot improve by repeating this
// connection's official retry loop: no candidate, a deterministic key error,
// or an unsafe replay. tunnel.shouldStopRetry recognizes StopRetry without
// knowing this package.
type stopRetryError struct {
	err error
}

func (e *stopRetryError) Error() string { return e.err.Error() }
func (e *stopRetryError) Unwrap() error { return e.err }
func (e *stopRetryError) StopRetry() bool {
	return true
}

func stopRetry(err error) error {
	if err == nil {
		return nil
	}
	return &stopRetryError{err: err}
}

// failurePhase separates a first payload write failure from a first read
// failure before any response. Neither triggers quota queries nor creates retry state shared with another connection.
type failurePhase uint8

const (
	failureFirstWrite failurePhase = iota
	failureFirstRead
)

func (p failurePhase) String() string {
	switch p {
	case failureFirstWrite:
		return "write"
	case failureFirstRead:
		return "read"
	default:
		return "unknown"
	}
}

// dialSession schedules one candidate per official retry call; it never performs I/O itself.
type dialSession struct {
	strategy *Strategy
	key      string
	host     string
	metadata *C.Metadata

	order   []string
	blocked map[string]struct{}

	flow       string
	attempts   int
	lastFailed string

	handle         *Handle
	originalName   string
	fresh          bool
	originalServer string
	round          int
	used           map[string]int
	normalPending  bool
	lastAttempt    string

	initMu      sync.Mutex
	initialized bool
	initErr     error

	finishOnce sync.Once
	mu         sync.Mutex
	exhausted  bool
	released   bool
}

func newDialSession(strategy *Strategy, key, host string, metadata *C.Metadata) *dialSession {
	flow := ""
	if strategy.diagEnabled() {
		flow = newDiagFlowID()
	}
	return &dialSession{
		strategy: strategy,
		key:      key,
		host:     host,
		flow:     flow,
		blocked:  strategy.blacklistedSet(metadata),
		metadata: metadata.Clone(),
	}
}

// ensureInit acquires the website binding once. Acquire is the only place a
// new binding is chosen; the session never re-draws weights per attempt.
func (s *dialSession) ensureInit(candidates []C.Proxy) error {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return s.initErr
	}
	s.initialized = true
	if len(candidates) == 0 {
		s.initErr = stopRetry(ErrNoAvailableCandidates)
		return s.initErr
	}

	pool := s.strategy.newScopedCandidates(candidates, s.metadata)
	handle, err := s.strategy.cache.Acquire(s.key,
		func() (string, error) {
			return s.strategy.chooseFresh(candidates, pool, s.key, s.flow)
		},
		func(name string) bool {
			return s.strategy.bindingUsable(name, candidates)
		},
	)
	if err != nil {
		s.initErr = stopRetry(err)
		return s.initErr
	}

	s.handle = handle
	s.originalName = handle.ProxyName()
	s.fresh = handle.Fresh()
	if !s.fresh {
		s.strategy.diagAddCount(s.originalName, diagMetricCacheReuse, 1)
	}
	s.originalServer = s.strategy.nodeIDs[s.originalName]
	s.order = s.rotationOrder(candidates)
	s.used = map[string]int{}
	s.round = 1
	s.normalPending = true
	if s.fresh && len(pool) == 0 {
		s.round = 2
		s.normalPending = false
	}
	log.Debugln("weighted-sticky [%s]: key=%q -> %q (generation %d, fresh %v, host %q)",
		s.strategy.name, s.key, s.originalName, handle.Generation(), s.fresh, s.host)
	return nil
}

// rotationOrder keeps the original proxy, its server siblings, then other servers in configured order.
func (s *dialSession) rotationOrder(candidates []C.Proxy) []string {
	var order []string
	if _, ok := findCandidate(candidates, s.originalName); ok {
		order = append(order, s.originalName)
	}
	present := make(map[string]bool, len(candidates))
	for _, p := range candidates {
		present[p.Name()] = true
	}
	appendNode := func(id string) {
		for _, name := range s.strategy.byNode[id] {
			if name != s.originalName && present[name] {
				order = append(order, name)
			}
		}
	}
	appendNode(s.originalServer)
	for _, node := range s.strategy.config.Nodes {
		if node.ID != s.originalServer {
			appendNode(node.ID)
		}
	}
	return order
}

func (s *dialSession) firstRoundLimit(name string) int {
	if !s.fresh && s.strategy.nodeIDs[name] == s.originalServer {
		return 2
	}
	return 1
}

func (s *dialSession) firstRoundCandidates(current []C.Proxy) []C.Proxy {
	var candidates []C.Proxy
	for _, name := range s.order {
		p, ok := findCandidate(current, name)
		if ok && s.used[name] < s.firstRoundLimit(name) && s.strategy.alive(p) {
			candidates = append(candidates, p)
		}
	}
	return preferNonBlacklisted(candidates, s.blocked)
}

func (s *dialSession) take(proxy C.Proxy) C.Proxy {
	s.used[proxy.Name()]++
	s.lastAttempt = proxy.Name()
	s.attempts++
	if s.strategy.diagEnabled() {
		s.strategy.diagEmit("selection.use", s.flow, map[string]any{"node": proxy.Name(), "server_id": s.strategy.nodeID(proxy), "round": s.round, "attempt": s.attempts})
	}
	return proxy
}

func (s *dialSession) next(current []C.Proxy) (C.Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || s.exhausted {
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	if s.normalPending {
		s.normalPending = false
		if p, ok := findCandidate(current, s.originalName); ok && s.strategy.alive(p) {
			return s.take(p), nil
		}
	}
	if s.round == 1 {
		if !s.fresh && s.strategy.nodeIDs[s.lastAttempt] == s.originalServer && s.used[s.lastAttempt] == 1 {
			if p, ok := findCandidate(current, s.lastAttempt); ok && s.strategy.alive(p) {
				return s.take(p), nil
			}
		}
		if pool := s.firstRoundCandidates(current); len(pool) > 0 {
			return s.take(pool[0]), nil
		}
		s.round = 2
		s.used = map[string]int{}
	}
	for _, name := range s.order {
		if s.used[name] == 0 {
			if p, ok := findCandidate(current, name); ok {
				return s.take(p), nil
			}
		}
	}
	s.exhausted = true
	return nil, stopRetry(ErrNoAvailableCandidates)
}

func (s *dialSession) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// noteFailure and noteSuccess maintain observation state for switch detection.
// They never change the attempt order or retry control flow.
func (s *dialSession) noteFailure(proxy C.Proxy) {
	if proxy == nil || !s.strategy.diagEnabled() {
		return
	}
	s.mu.Lock()
	s.lastFailed = proxy.Name()
	s.mu.Unlock()
}

func (s *dialSession) noteSuccess(proxy C.Proxy) (bool, string) {
	if proxy == nil || !s.strategy.diagEnabled() {
		return false, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastFailed == "" {
		return false, ""
	}
	if s.lastFailed == proxy.Name() {
		return false, ""
	}
	return true, s.lastFailed
}

// install preserves generation isolation; quota observations never veto an established connection.
func (s *dialSession) install(used C.Proxy) error {
	if s.strategy.candidates != nil {
		current := s.strategy.candidates()
		s.strategy.reconcileCandidates(current)
		if p, ok := findCandidate(current, used.Name()); !ok || !sameProxyObject(p, used) {
			return nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle == nil {
		return stopRetry(ErrNoAvailableCandidates)
	}
	if used.Name() == s.handle.ProxyName() {
		return nil
	}
	newHandle, installed := s.strategy.cache.Rebind(s.key, s.handle.Generation(), used.Name())
	if !installed {
		return nil
	}
	s.handle.Release()
	s.handle = newHandle
	return nil
}

// connectionHandle gives the established connection its own reference to the
// current binding. The retry scope releases its reference in Finish, so the
// connection can outlive the official loop without a leaked reservation.
func (s *dialSession) connectionHandle() *Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil
	}
	return s.strategy.cache.Ref(s.handle.binding)
}

func (s *dialSession) originalNodeName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.originalName
}

// release drops the retry-scope reference. It is idempotent and safe after a
// successful install replaced the handle.
func (s *dialSession) release() {
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.released = true
	handle := s.handle
	s.handle = nil
	s.mu.Unlock()
	if handle != nil {
		handle.Release()
	}
}

// sessionFor returns the connection's session. Inside the official loop the
// state lives in the typed retry context; a direct dial (for example the
// rematch metadata probe) gets a one-attempt session and cannot silently
// inherit another connection's position.
func (s *Strategy) sessionFor(ctx context.Context, key, host string, candidates []C.Proxy, metadata *C.Metadata) (*dialSession, func(), error) {
	state, inRetry := retrystate.From(ctx)
	if !inRetry {
		session := newDialSession(s, key, host, metadata)
		if err := session.ensureInit(candidates); err != nil {
			session.release()
			return nil, nil, err
		}
		return session, session.release, nil
	}

	value := state.Value(func() any {
		return newDialSession(s, key, host, metadata)
	})
	session, ok := value.(*dialSession)
	if !ok {
		return nil, nil, stopRetry(ErrNoAvailableCandidates)
	}
	if err := session.ensureInit(candidates); err != nil {
		return nil, nil, err
	}
	session.finishOnce.Do(func() {
		state.OnFinish(session.release)
	})
	return session, nil, nil
}

// firstFailureHook runs after a connection failed on its first write or first
// read. The current request is not replayed and no state is shared with the
// next connection; the failure is observed without replaying the request or changing health.
func (s *Strategy) firstFailureHook(proxy C.Proxy, session *dialSession, attempt int) func(failurePhase, error) {
	if proxy == nil {
		return nil
	}
	return func(phase failurePhase, err error) {
		log.Debugln("weighted-sticky [%s]: first %s on %q failed: %v", s.name, phase, proxy.Name(), err)
		if s.diagEnabled() {
			flow := ""
			if session != nil {
				flow = session.flow
			}
			s.diagEmit("first_io.failure", flow, map[string]any{
				"node":        proxy.Name(),
				"stage":       phase.String(),
				"error_class": diagErrorClass(err),
				"attempt":     attempt,
			})
			s.diagAddCount(proxy.Name(), diagMetricFailure, 1)
		}
		if session != nil {
			session.noteFailure(proxy)
		}
	}
}
