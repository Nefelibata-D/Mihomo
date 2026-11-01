package weightedsticky

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	diagMetricDraw       = "draw"
	diagMetricCacheReuse = "cache_reuse"
	diagMetricAttempt    = "attempt"
	diagMetricFailure    = "failure"
	diagMetricSwitchOpen = "switch_open"
)

// diagConfig is the runtime configuration summary recorded when a strategy
// starts. It deliberately has no field for the control URL or credential.
type diagConfig struct {
	DefaultWeight     int
	Weights           map[string]int
	IdleTimeout       time.Duration
	NodeIDs           map[string]string
	BlacklistEnabled  bool
	ManagementEnabled bool
}

// diagEvent is one observation. The build-tag-selected writer adds the run ID
// and UTC timestamp.
type diagEvent struct {
	Name     string
	Group    string
	Instance string
	Flow     string
	Fields   map[string]any
	Time     time.Time
	flushed  chan struct{}
}

// diagEmitter is the observation surface used by the strategy, session and
// dial proxy. Production builds use noopDiag; a beta_diag build uses the
// process writer.
type diagEmitter interface {
	Enabled() bool
	KeyID(key string) string
	Register(instance, group string, config diagConfig)
	Unregister(instance string)
	Emit(event diagEvent)
	AddCount(instance, node, metric string, n uint64)
}

type noopDiag struct{}

func (noopDiag) Enabled() bool                           { return false }
func (noopDiag) KeyID(string) string                     { return "" }
func (noopDiag) Register(string, string, diagConfig)     {}
func (noopDiag) Unregister(string)                       {}
func (noopDiag) Emit(diagEvent)                          {}
func (noopDiag) AddCount(string, string, string, uint64) {}

type diagNodeWeight struct {
	Node   string `json:"node"`
	Weight int    `json:"weight"`
}

// diagSequence provides process-local instance and flow IDs. It is independent
// of the strategy's random source, so diagnostics never perturb a draw.
var diagSequence atomic.Uint64

func newDiagInstanceID() string { return fmt.Sprintf("i%d", diagSequence.Add(1)) }
func newDiagFlowID() string     { return fmt.Sprintf("f%d", diagSequence.Add(1)) }

func (c diagConfig) fields() map[string]any {
	weights := make(map[string]int, len(c.Weights))
	for name, weight := range c.Weights {
		weights[name] = weight
	}
	nodeIDs := make(map[string]string, len(c.NodeIDs))
	for name, node := range c.NodeIDs {
		nodeIDs[name] = node
	}
	return map[string]any{
		"default_weight":       c.DefaultWeight,
		"weights":              weights,
		"idle_timeout_seconds": int64(c.IdleTimeout / time.Second),
		"node_ids":             nodeIDs,
		"blacklist_enabled":    c.BlacklistEnabled,
		"management_enabled":   c.ManagementEnabled,
	}
}

func (s *Strategy) diagEnabled() bool {
	return s.diag != nil && s.diag.Enabled()
}

func (s *Strategy) diagEmit(name, flow string, fields map[string]any) {
	if !s.diagEnabled() {
		return
	}
	s.diag.Emit(diagEvent{
		Name:     name,
		Group:    s.name,
		Instance: s.diagInstance,
		Flow:     flow,
		Fields:   fields,
		Time:     time.Now().UTC(),
	})
}

func (s *Strategy) diagAddCount(node, metric string, n uint64) {
	if node == "" || metric == "" || n == 0 || !s.diagEnabled() {
		return
	}
	s.diag.AddCount(s.diagInstance, node, metric, n)
}

func (s *Strategy) diagKeyID(key string) string {
	if key == "" || !s.diagEnabled() {
		return ""
	}
	return s.diag.KeyID(key)
}

func (s *Strategy) diagStatus(proxy C.Proxy) AccountStatus {
	if proxy == nil || s.policy == nil {
		return AccountStatusUnknown
	}
	nodeID := s.nodeID(proxy)
	if nodeID == "" {
		return AccountStatusUnknown
	}
	return s.policy.Get(nodeID).Status
}

func (s *Strategy) diagConfig() diagConfig {
	return diagConfig{
		DefaultWeight:     s.config.DefaultWeight,
		Weights:           s.config.Weights,
		IdleTimeout:       s.config.IdleTimeout,
		NodeIDs:           s.nodeIDs,
		BlacklistEnabled:  s.config.Blacklist != nil,
		ManagementEnabled: s.policy != nil,
	}
}

func (s *Strategy) diagPool(pool []C.Proxy) ([]diagNodeWeight, int) {
	weights := make([]diagNodeWeight, 0, len(pool))
	total := 0
	for _, proxy := range pool {
		weight := s.weightOf(proxy)
		if weight <= 0 {
			continue
		}
		weights = append(weights, diagNodeWeight{Node: proxy.Name(), Weight: weight})
		total += weight
	}
	return weights, total
}

func diagCandidateNames(candidates []C.Proxy) []string {
	names := make([]string, 0, len(candidates))
	for _, proxy := range candidates {
		names = append(names, proxy.Name())
	}
	return names
}

func diagBlacklistHits(candidates []C.Proxy, blocked map[string]struct{}) []string {
	hits := make([]string, 0, len(blocked))
	if len(blocked) == 0 {
		return hits
	}
	for _, proxy := range candidates {
		if _, ok := blocked[proxy.Name()]; ok {
			hits = append(hits, proxy.Name())
		}
	}
	sort.Strings(hits)
	return hits
}

// diagSite returns the normalized website identity already embedded in the
// binding key. A destination IP is deliberately not recorded; the anonymous
// binding ID still distinguishes it within a run.
func diagSite(key string) (kind, value string) {
	parts := strings.Split(key, "\x00")
	if len(parts) < 2 {
		return "unknown", ""
	}
	kind = parts[len(parts)-2]
	value = parts[len(parts)-1]
	switch kind {
	case "site", "domain":
		return kind, value
	case "ip":
		return "ip", ""
	default:
		return "unknown", ""
	}
}

func diagErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "other"
}

func diagDrawErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrNoAvailableCandidates):
		return "no_candidate"
	case errors.Is(err, ErrWeightOverflow):
		return "weight_overflow"
	default:
		return "draw_error"
	}
}
