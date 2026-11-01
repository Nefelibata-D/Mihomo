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
// failure before any response. Both only trigger the rate-limited management
// query; they never create state shared with another connection.
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

// dialSession is one connection's selection state. The official retry loop
// calls the strategy once per attempt; the session advances exactly one node
// per call. It is never shared by concurrent connections and never stored in
// the website cache as a retry counter.
//
// The first node is the cached binding (or a weighted new selection). An
// existing binding gets three sticky attempts including the first; a fresh
// binding gets one. After the sticky head the session follows the stable
// provider order, skipping candidates that are no longer admitted or that the
// site-blacklist excludes while a non-blacklisted alternative exists. The
// official retry count and context remain the only budget.
type dialSession struct {
	strategy *Strategy
	key      string
	host     string

	order   []string
	blocked map[string]struct{}

	flow        string
	attempts    int
	graceLogged bool
	lastFailed  string

	handle       *Handle
	originalName string
	fresh        bool
	sticky       int
	rotation     int

	initMu      sync.Mutex
	initialized bool
	initErr     error

	finishOnce sync.Once
	mu         sync.Mutex
	exhausted  bool
	released   bool
}

func newDialSession(strategy *Strategy, key, host string) *dialSession {
	flow := ""
	if strategy.diagEnabled() {
		flow = newDiagFlowID()
	}
	return &dialSession{
		strategy: strategy,
		key:      key,
		host:     host,
		flow:     flow,
		blocked:  strategy.blacklistedSet(host),
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

	s.order = make([]string, 0, len(candidates))
	for _, proxy := range candidates {
		s.order = append(s.order, proxy.Name())
	}

	handle, err := s.strategy.cache.Acquire(s.key,
		func() (string, error) {
			return s.strategy.chooseFresh(candidates, s.key, s.host, s.flow)
		},
		func(name string) bool {
			proxy, ok := findCandidate(candidates, name)
			return ok && s.strategy.bindingUsable(proxy)
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
	s.sticky = 3
	if s.fresh {
		s.sticky = 1
	}
	for i, name := range s.order {
		if name == s.originalName {
			s.rotation = (i + 1) % len(s.order)
			break
		}
	}
	log.Debugln("weighted-sticky [%s]: key=%q -> %q (generation %d, fresh %v, host %q)",
		s.strategy.name, s.key, s.originalName, handle.Generation(), s.fresh, s.host)
	return nil
}

// next returns exactly one candidate for this official attempt. The sticky
// head is consumed first; once it is gone, one full rotation scan is allowed.
// A candidate is re-checked against current admission and the site-blacklist
// at this moment, not from a plan snapshot.
func (s *dialSession) next(current []C.Proxy) (C.Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	diagOn := s.strategy.diagEnabled()

	if s.handle == nil || s.exhausted {
		return nil, stopRetry(ErrNoAvailableCandidates)
	}

	if s.sticky > 0 {
		if proxy, ok := findCandidate(current, s.originalName); ok && s.eligible(proxy) {
			s.sticky--
			if diagOn {
				s.attempts++
			}
			if diagOn && !s.fresh && !s.graceLogged && s.strategy.diagStatus(proxy) == AccountStatusGrace {
				s.graceLogged = true
				s.strategy.diagEmit("selection.use", s.flow, map[string]any{
					"reason":   "grace_reuse",
					"node":     proxy.Name(),
					"original": s.originalName,
					"attempt":  s.attempts,
				})
			}
			return proxy, nil
		}
		// The bound node was skipped. Sticky priority is offered once at the
		// head of the connection; it is not deferred to a later rotation.
		s.sticky = 0
		if diagOn {
			s.strategy.diagEmit("selection.blocked", s.flow, map[string]any{
				"reason":         "original_skipped",
				"node":           s.originalName,
				"original":       s.originalName,
				"attempt":        s.attempts + 1,
				"blacklist_hits": diagBlacklistHits(current, s.blocked),
			})
		}
	}

	if len(s.order) == 0 {
		s.exhausted = true
		if diagOn {
			s.strategy.diagEmit("selection.blocked", s.flow, map[string]any{
				"reason":         "no_candidate",
				"original":       s.originalName,
				"blacklist_hits": diagBlacklistHits(current, s.blocked),
			})
		}
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	for i := 0; i < len(s.order); i++ {
		name := s.order[s.rotation]
		s.rotation = (s.rotation + 1) % len(s.order)
		proxy, ok := findCandidate(current, name)
		if !ok {
			// The provider removed this candidate after the connection took its
			// order snapshot. Skip it; a new candidate joins the next connection.
			continue
		}
		if s.rotationEligible(current, proxy) {
			if diagOn {
				s.attempts++
			}
			if diagOn {
				s.strategy.diagEmit("selection.use", s.flow, map[string]any{
					"reason":         "rotation",
					"node":           proxy.Name(),
					"original":       s.originalName,
					"attempt":        s.attempts,
					"blacklist_hits": diagBlacklistHits(current, s.blocked),
				})
			}
			return proxy, nil
		}
	}

	s.exhausted = true
	if diagOn {
		s.strategy.diagEmit("selection.blocked", s.flow, map[string]any{
			"reason":         "no_candidate",
			"original":       s.originalName,
			"blacklist_hits": diagBlacklistHits(current, s.blocked),
		})
	}
	return nil, stopRetry(ErrNoAvailableCandidates)
}

func (s *dialSession) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// noteFailure and noteSuccess maintain observation state for switch detection.
// They never change the attempt order, admission rules or retry control flow.
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

// eligible keeps the connection's original binding qualified under grace even
// after the session rotates through other nodes. Every other node needs a
// new-binding admission, which grace rejects.
func (s *dialSession) eligible(proxy C.Proxy) bool {
	if proxy.Name() == s.originalName {
		if s.fresh {
			return s.strategy.newBindingEligible(proxy)
		}
		return s.strategy.existingBindingEligible(proxy)
	}
	return s.strategy.newBindingEligible(proxy)
}

// rotationEligible enforces the per-connection blacklist scope. A blacklisted
// node is skipped while any non-blacklisted eligible node exists; the cached
// node still receives its sticky attempts before rotation starts.
func (s *dialSession) rotationEligible(current []C.Proxy, proxy C.Proxy) bool {
	if !s.eligible(proxy) {
		return false
	}
	if _, excluded := s.blocked[proxy.Name()]; !excluded {
		return true
	}
	for _, candidate := range current {
		if !s.eligible(candidate) {
			continue
		}
		if _, excluded := s.blocked[candidate.Name()]; !excluded {
			return false
		}
	}
	return true
}

// admission is the install-time counterpart of eligible. The connection's
// original binding keeps its existing-binding qualification under grace for
// the whole connection; every other node and every fresh binding needs new
// admission. Network health is not re-checked here: a successful dial is newer
// evidence than the last health record.
func (s *dialSession) admission(proxy C.Proxy) bool {
	if proxy == nil {
		return false
	}
	if proxy.Name() == s.originalName && !s.fresh {
		return s.strategy.nodeAdmitsExisting(proxy)
	}
	return s.strategy.nodeAdmitsNew(proxy)
}

// install publishes the node that actually carried a successful dial. It is
// the same generation-conditioned Rebind used before; a late success cannot
// overwrite a newer shared binding. Grace may keep the connection's original
// binding but never publishes a new one, even if the status changed during the
// dial.
func (s *dialSession) install(used C.Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle == nil {
		return stopRetry(ErrNoAvailableCandidates)
	}
	if !s.admission(used) {
		return ErrNodeNotApproved
	}
	if used.Name() == s.handle.ProxyName() {
		return nil
	}
	newHandle, installed, err := s.strategy.cache.Rebind(s.key, s.handle.Generation(), used.Name(), func(name string) bool {
		return name == used.Name() && s.admission(used)
	})
	if err != nil {
		return err
	}
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
func (s *Strategy) sessionFor(ctx context.Context, key, host string, candidates []C.Proxy) (*dialSession, func(), error) {
	state, inRetry := retrystate.From(ctx)
	if !inRetry {
		session := newDialSession(s, key, host)
		if err := session.ensureInit(candidates); err != nil {
			session.release()
			return nil, nil, err
		}
		return session, session.release, nil
	}

	value := state.Value(func() any {
		return newDialSession(s, key, host)
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

// attemptFailed starts the existing rate-limited management query. A failed
// dial is not interpreted as a health result; only the management response can
// change account admission.
func (s *Strategy) attemptFailed(proxy C.Proxy) {
	if proxy == nil || s.validator == nil {
		return
	}
	nodeID := s.nodeID(proxy)
	if nodeID == "" {
		return
	}
	s.validator.TriggerFailure(nodeID)
}

// firstFailureHook runs after a connection failed on its first write or first
// read. The current request is not replayed and no state is shared with the
// next connection; the failure only starts the rate-limited management query.
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
		s.attemptFailed(proxy)
	}
}
