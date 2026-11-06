package weightedsticky

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var (
	// ErrNestedProxyGroup rejects a proxy group as a candidate: a group may
	// switch egress on its own, so binding its name would not bind the exit.
	ErrNestedProxyGroup = errors.New("weighted-sticky: nested proxy group is not a candidate")

	// ErrDuplicateCandidateName rejects two distinct adapters sharing one name;
	// the binding stores names, so such a pair cannot be represented.
	ErrDuplicateCandidateName = errors.New("weighted-sticky: duplicate candidate name")

	// ErrNodeNotApproved reports that a successful dial finished after the node
	// stopped being approved for this connection. The connection must not be
	// published as a shared binding or treated as admitted.
	ErrNodeNotApproved = errors.New("weighted-sticky: node is no longer approved")
)

// StrategyOptions configures a Strategy. Now, RandIntn and Alive exist so tests
// can use a virtual clock, deterministic draws and a deterministic official
// health source; nil means the production implementation.
type StrategyOptions struct {
	Name     string
	Config   *Options
	TestURL  string
	Now      func() time.Time
	RandIntn func(int) int
	Alive    func(C.Proxy) bool

	// Clock and Checker are injection points for deterministic tests.
	// Production leaves them nil and uses the real clock and control client.
	Clock   Clock
	Checker StatusChecker
}

// Strategy implements the strategyFn shape expected by LoadBalance. All state
// is owned by the strategy instance, so one proxy group can never read another
// group's bindings or account states.
type Strategy struct {
	name     string
	config   *Options
	cache    *Cache
	randIntn func(int) int
	alive    func(C.Proxy) bool

	diag         diagEmitter
	diagInstance string

	policy    *PolicyStore
	validator *Validator
	nodeIDs   map[string]string
	byNode    map[string][]string

	mu        sync.Mutex
	started   bool
	closed    bool
	closeOnce sync.Once

	// reconcileMu guards the last observed candidate list. Reconciliation is
	// only needed when a provider adds, removes or replaces a candidate; the
	// list is at most 32 entries by design.
	reconcileMu    sync.Mutex
	lastCandidates []C.Proxy
}

func NewStrategy(options StrategyOptions) (*Strategy, error) {
	if options.Config == nil {
		return nil, errors.New("weighted-sticky: strategy config is nil")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	randIntn := options.RandIntn
	if randIntn == nil {
		randIntn = rand.Intn
	}
	alive := options.Alive
	if alive == nil {
		alive = func(proxy C.Proxy) bool {
			return proxy.AliveForTestUrl(options.TestURL)
		}
	}
	strategy := &Strategy{
		name:         options.Name,
		config:       options.Config,
		cache:        NewCache(options.Config.MaxBindings, options.Config.IdleTimeout, now),
		randIntn:     randIntn,
		alive:        alive,
		diag:         newProcessDiag(),
		diagInstance: newDiagInstanceID(),
	}

	resilience := options.Config.Resilience
	if resilience == nil {
		// Without a management block there is no account admission. The
		// subscription blacklist, official retry loop, and health ordering
		// still apply.
		return strategy, nil
	}

	clock := options.Clock
	if clock == nil {
		clock = realClock{}
	}
	checker := options.Checker
	if checker == nil {
		control, err := NewControlClient(ControlClientOptions{
			BaseURL: resilience.Control.BaseURL,
			UUID:    resilience.Control.UUID,
			Timeout: resilience.Control.Timeout,
		})
		if err != nil {
			return nil, err
		}
		checker = control
	}

	strategy.policy = NewPolicyStore()
	strategy.nodeIDs = resilience.Control.NodeIDs
	strategy.byNode = map[string][]string{}
	for name, node := range strategy.nodeIDs {
		strategy.byNode[node] = append(strategy.byNode[node], name)
	}

	nodes := make([]string, 0, len(strategy.byNode))
	for node := range strategy.byNode {
		nodes = append(nodes, node)
	}
	validator, err := NewValidator(ValidatorOptions{
		Checker:       checker,
		Store:         strategy.policy,
		NodeIDs:       nodes,
		MinInterval:   resilience.Control.MinInterval,
		GraceInterval: resilience.Control.GraceInterval,
		Clock:         clock,
		OnStatusChange: func(nodeID string, from, to AccountStatus) {
			if to == AccountStatusDisabled {
				for _, proxyName := range strategy.byNode[nodeID] {
					strategy.cache.InvalidateNode(proxyName)
				}
				log.Debugln("weighted-sticky [%s]: node %s for this account is disabled; bindings invalidated", strategy.name, nodeID)
			}
			if strategy.diagEnabled() {
				strategy.diagEmit("status.change", "", map[string]any{
					"node_id": nodeID,
					"from":    from.String(),
					"to":      to.String(),
				})
			}
		},
	})
	if err != nil {
		return nil, err
	}
	strategy.validator = validator
	return strategy, nil
}

// Start begins the status queries this instance owns. It is idempotent, and a
// strategy closed before Start never starts.
func (s *Strategy) Start() {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.diag.Register(s.diagInstance, s.name, s.diagConfig())
	validator := s.validator
	s.mu.Unlock()
	if validator != nil {
		validator.Start()
	}
}

// Close cancels status queries and timers owned by this instance. It is
// idempotent and rejects work from late callbacks.
func (s *Strategy) Close() {
	s.mu.Lock()
	s.closed = true
	started := s.started
	s.mu.Unlock()
	s.closeOnce.Do(func() {
		if s.validator != nil {
			s.validator.Close()
		}
		if started {
			s.diag.Unregister(s.diagInstance)
		}
	})
}

// SelectProxy is installed as LoadBalance's strategyFn. A failure to build a
// key, find a candidate or allocate a binding is returned as an
// unavailableProxy whose dial fails; this strategy never returns nil and never
// falls back to the first candidate or DIRECT.
func (s *Strategy) SelectProxy(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
	candidates, err := buildWeightedCandidates(proxies)
	if err != nil {
		return s.unavailable(err)
	}
	if len(candidates) == 0 {
		if touch && s.diagEnabled() {
			s.diagEmit("selection.blocked", "", map[string]any{"reason": "no_candidates"})
		}
		return s.unavailable(ErrNoAvailableCandidates)
	}

	key, host, err := s.bindingKey(metadata)
	if err != nil {
		return s.unavailable(err)
	}

	if !touch {
		return s.preview(candidates, key, metadata)
	}

	// Provider deletions and replacements are reconciled only on a real
	// acquisition. The preview path stays read-only.
	s.reconcileCandidates(candidates)

	// Selection itself is deferred to DialContext, where the official retry
	// state identifies this connection. The preview only supplies the proxy
	// metadata (name/type) and fails early when no candidate is possible.
	preview := s.preview(candidates, key, metadata)
	if _, unavailable := preview.(*unavailableProxy); unavailable {
		if touch && s.diagEnabled() {
			s.diagEmit("selection.blocked", "", map[string]any{
				"reason":         "no_admitted_candidate",
				"candidates":     diagCandidateNames(candidates),
				"blacklist_hits": diagBlacklistHits(candidates, s.blacklistedSet(metadata)),
			})
		}
		return preview
	}
	return &resilientProxy{
		Proxy:      preview,
		strategy:   s,
		key:        key,
		host:       host,
		candidates: candidates,
	}
}

// bindingKey resolves the website cache key and the request host used by the
// blacklist. The cache key includes the inbound identity, never the process.
func (s *Strategy) bindingKey(metadata *C.Metadata) (key, host string, err error) {
	key, err = BindingKey(metadata, s.config.Sites)
	if err != nil {
		return "", "", err
	}
	host, err = siteHost(metadata)
	if err != nil {
		return "", "", err
	}
	return key, host, nil
}

// preview implements Unwrap(metadata, false): it reports the currently bound
// candidate when one exists, otherwise a deterministic eligible candidate for
// type inspection. It neither creates nor renews a binding.
func (s *Strategy) preview(candidates []C.Proxy, key string, metadata *C.Metadata) C.Proxy {
	if name, ok := s.cache.Lookup(key); ok {
		if proxy, found := findCandidate(candidates, name); found && s.bindingUsable(proxy) {
			return proxy
		}
	}

	scoped := s.newScopedCandidates(candidates, metadata)
	for _, proxy := range scoped {
		if s.alive(proxy) {
			return proxy
		}
	}
	if len(scoped) > 0 {
		return scoped[0]
	}
	return s.unavailable(ErrNoAvailableCandidates)
}

// chooseFresh chooses the first node of a new binding. Weight only affects this
// one draw. Official health orders the draw: healthy candidates are preferred
// when any exist, but when every record says unhealthy the strategy still
// chooses among the admitted candidates and lets the actual dial decide.
func (s *Strategy) chooseFresh(candidates []C.Proxy, key string, metadata *C.Metadata, flow string) (string, error) {
	diagOn := s.diagEnabled()
	var blocked map[string]struct{}
	if diagOn {
		blocked = s.blacklistedSet(metadata)
	}

	scoped := s.newScopedCandidates(candidates, metadata)
	if len(scoped) == 0 {
		if diagOn {
			s.diagEmit("selection.blocked", flow, map[string]any{
				"reason":         "no_admitted_candidate",
				"candidates":     diagCandidateNames(candidates),
				"blacklist_hits": diagBlacklistHits(candidates, blocked),
			})
		}
		return "", ErrNoAvailableCandidates
	}

	pool := scoped
	healthy := make([]C.Proxy, 0, len(scoped))
	for _, proxy := range scoped {
		if s.alive(proxy) {
			healthy = append(healthy, proxy)
		}
	}
	if len(healthy) > 0 {
		pool = healthy
	}

	if log.Level() <= log.DEBUG {
		names := make([]string, 0, len(pool))
		for _, proxy := range pool {
			names = append(names, proxy.Name())
		}
		log.Debugln("weighted-sticky [%s]: fresh candidate pool %v", s.name, names)
	}

	selected, err := SelectCandidate(pool, s.config.Weights, s.config.DefaultWeight, s.randIntn)
	if err != nil {
		if diagOn {
			s.diagEmit("selection.blocked", flow, map[string]any{
				"reason":         "draw_failed",
				"error_class":    diagDrawErrorClass(err),
				"candidates":     diagCandidateNames(candidates),
				"blacklist_hits": diagBlacklistHits(candidates, blocked),
			})
		}
		return "", err
	}

	if diagOn {
		healthMode := "all_unhealthy"
		if len(healthy) == len(scoped) {
			healthMode = "all_healthy"
		} else if len(healthy) > 0 {
			healthMode = "healthy_only"
		}
		poolWeights, total := s.diagPool(pool)
		blacklistFallback := false
		for _, proxy := range scoped {
			if _, ok := blocked[proxy.Name()]; ok {
				blacklistFallback = true
				break
			}
		}
		siteType, site := diagSite(key)
		s.diagEmit("selection.draw", flow, map[string]any{
			"binding":            s.diagKeyID(key),
			"site_type":          siteType,
			"site":               site,
			"pool":               poolWeights,
			"total_weight":       total,
			"selected":           selected.Name(),
			"health_mode":        healthMode,
			"blacklist_hits":     diagBlacklistHits(candidates, blocked),
			"blacklist_fallback": blacklistFallback,
		})
		s.diagAddCount(selected.Name(), diagMetricDraw, 1)
	}
	return selected.Name(), nil
}

// newScopedCandidates applies account admission and the site-blacklist rule.
// Only positive-weight nodes that may receive a new binding are considered.
// Blacklisted nodes enter the candidate set only when no non-blacklisted
// admitted node exists.
func (s *Strategy) newScopedCandidates(candidates []C.Proxy, metadata *C.Metadata) []C.Proxy {
	admitted := make([]C.Proxy, 0, len(candidates))
	for _, proxy := range candidates {
		if s.newBindingEligible(proxy) {
			admitted = append(admitted, proxy)
		}
	}
	if len(admitted) == 0 {
		return nil
	}

	blocked := s.blacklistedSet(metadata)
	if len(blocked) == 0 {
		return admitted
	}
	nonBlocked := make([]C.Proxy, 0, len(admitted))
	for _, proxy := range admitted {
		if _, excluded := blocked[proxy.Name()]; !excluded {
			nonBlocked = append(nonBlocked, proxy)
		}
	}
	if len(nonBlocked) > 0 {
		return nonBlocked
	}
	return admitted
}

func (s *Strategy) blacklistedSet(metadata *C.Metadata) map[string]struct{} {
	if metadata == nil || s.config.Blacklist == nil {
		return nil
	}
	return s.config.Blacklist.Match(metadata)
}

// bindingUsable decides whether an existing cached binding may serve a new
// connection. Health and the site-blacklist never invalidate a binding:
// stickiness wins until the account is explicitly disabled or the idle window
// expires.
func (s *Strategy) bindingUsable(proxy C.Proxy) bool {
	return s.existingBindingEligible(proxy)
}

func (s *Strategy) newBindingEligible(proxy C.Proxy) bool {
	if proxy == nil || s.weightOf(proxy) <= 0 {
		return false
	}
	return s.nodeAdmitsNew(proxy)
}

func (s *Strategy) existingBindingEligible(proxy C.Proxy) bool {
	if proxy == nil {
		return false
	}
	return s.nodeAdmitsExisting(proxy)
}

func (s *Strategy) nodeAdmitsNew(proxy C.Proxy) bool {
	if proxy == nil {
		return false
	}
	if s.policy == nil {
		// Without a management block every candidate is admitted by the
		// subscription itself; the server remains the final authority.
		return true
	}
	nodeID := s.nodeID(proxy)
	return nodeID != "" && s.policy.AllowsNewBinding(nodeID)
}

func (s *Strategy) nodeAdmitsExisting(proxy C.Proxy) bool {
	if proxy == nil {
		return false
	}
	if s.policy == nil {
		return true
	}
	nodeID := s.nodeID(proxy)
	return nodeID != "" && s.policy.AllowsExistingBinding(nodeID)
}

func (s *Strategy) nodeID(proxy C.Proxy) string {
	if proxy == nil || s.nodeIDs == nil {
		return ""
	}
	return s.nodeIDs[proxy.Name()]
}

// reconcileCandidates drops binding records for nodes the provider removed.
// It runs only when the candidate list actually changed, so the normal dial
// path pays only a length/identity comparison over at most 32 entries.
func (s *Strategy) reconcileCandidates(candidates []C.Proxy) {
	if len(candidates) == 0 {
		return
	}

	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if sameCandidateSnapshot(s.lastCandidates, candidates) {
		return
	}
	s.lastCandidates = append([]C.Proxy(nil), candidates...)

	keep := make(map[string]struct{}, len(candidates))
	for _, proxy := range candidates {
		keep[proxy.Name()] = struct{}{}
	}
	s.cache.PruneProxies(keep)
}

func sameCandidateSnapshot(a, b []C.Proxy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name() != b[i].Name() || !sameProxyObject(a[i], b[i]) {
			return false
		}
	}
	return true
}

func (s *Strategy) weightOf(proxy C.Proxy) int {
	if weight, ok := s.config.Weights[proxy.Name()]; ok {
		return weight
	}
	return s.config.DefaultWeight
}

func (s *Strategy) unavailable(err error) C.Proxy {
	return &unavailableProxy{name: s.name, err: err}
}

// CacheSize reports the number of live bindings. It exists for diagnostics and
// deterministic tests; it does not expose the cache itself.
func (s *Strategy) CacheSize() int {
	return s.cache.Size()
}

// buildWeightedCandidates deduplicates repeated references to the same proxy
// object, rejects two distinct proxies with one name and rejects proxy groups.
func buildWeightedCandidates(proxies []C.Proxy) ([]C.Proxy, error) {
	candidates := make([]C.Proxy, 0, len(proxies))
	seen := make(map[string]C.Proxy, len(proxies))

	for _, proxy := range proxies {
		if proxy == nil || proxy.Type() == C.Compatible {
			// COMPATIBLE is the group's empty fallback, not a real exit.
			continue
		}
		if isProxyGroupType(proxy.Type()) {
			return nil, fmt.Errorf("%w: %q", ErrNestedProxyGroup, proxy.Name())
		}
		if existing, ok := seen[proxy.Name()]; ok {
			if sameProxyObject(existing, proxy) {
				continue
			}
			return nil, fmt.Errorf("%w: %q", ErrDuplicateCandidateName, proxy.Name())
		}
		seen[proxy.Name()] = proxy
		candidates = append(candidates, proxy)
	}

	return candidates, nil
}

// StaticCandidateNames inspects the providers available at construction. It
// rejects nested groups and duplicate names early, and reports whether a
// dynamic provider can introduce names after this point.
func StaticCandidateNames(providers []P.ProxyProvider) ([]string, bool, error) {
	names := make([]string, 0)
	seen := make(map[string]C.Proxy)
	dynamic := false

	for _, provider := range providers {
		if provider.VehicleType() != P.Compatible {
			dynamic = true
		}
		for _, proxy := range provider.Proxies() {
			if isProxyGroupType(proxy.Type()) {
				return nil, false, fmt.Errorf("%w: %q", ErrNestedProxyGroup, proxy.Name())
			}
			if existing, ok := seen[proxy.Name()]; ok {
				if sameProxyObject(existing, proxy) {
					continue
				}
				return nil, false, fmt.Errorf("%w: %q", ErrDuplicateCandidateName, proxy.Name())
			}
			seen[proxy.Name()] = proxy
			names = append(names, proxy.Name())
		}
	}

	return names, dynamic, nil
}

func isProxyGroupType(adapterType C.AdapterType) bool {
	switch adapterType {
	case C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return true
	default:
		return false
	}
}

func sameProxyObject(a, b C.Proxy) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Kind() == reflect.Ptr && vb.Kind() == reflect.Ptr {
		return va.Pointer() == vb.Pointer()
	}
	return false
}

func findCandidate(candidates []C.Proxy, name string) (C.Proxy, bool) {
	for _, proxy := range candidates {
		if proxy.Name() == name {
			return proxy, true
		}
	}
	return nil, false
}

// unavailableProxy surfaces a selection error through the normal dial path.
// Its type is COMPATIBLE so LoadBalance.onDialFailed deliberately ignores it;
// an empty group is not a node failure.
type unavailableProxy struct {
	name string
	err  error
}

var _ C.Proxy = (*unavailableProxy)(nil)

func (p *unavailableProxy) Name() string                                    { return p.name }
func (p *unavailableProxy) Type() C.AdapterType                             { return C.Compatible }
func (p *unavailableProxy) Addr() string                                    { return "" }
func (p *unavailableProxy) SupportUDP() bool                                { return false }
func (p *unavailableProxy) SupportUOT() bool                                { return false }
func (p *unavailableProxy) ProxyInfo() C.ProxyInfo                          { return C.ProxyInfo{} }
func (p *unavailableProxy) IsL3Protocol(metadata *C.Metadata) bool          { return false }
func (p *unavailableProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy { return nil }
func (p *unavailableProxy) Adapter() C.ProxyAdapter                         { return p }
func (p *unavailableProxy) AliveForTestUrl(url string) bool                 { return false }
func (p *unavailableProxy) DelayHistory() []C.DelayHistory                  { return nil }
func (p *unavailableProxy) ExtraDelayHistories() map[string]C.ProxyState    { return nil }
func (p *unavailableProxy) LastDelayForTestUrl(url string) uint16           { return math.MaxUint16 }
func (p *unavailableProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	return 0, p.err
}

func (p *unavailableProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if p.err == nil {
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	return nil, stopRetry(p.err)
}

func (p *unavailableProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if p.err == nil {
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	return nil, stopRetry(p.err)
}

func (p *unavailableProxy) Close() error { return nil }

func (p *unavailableProxy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        p.name,
		"type":        p.Type().String(),
		"unavailable": true,
		"error":       p.err.Error(),
	})
}
