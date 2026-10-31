package weightedsticky

import (
	"sync"
	"time"
)

// AccountStatus is the admission state of one management account on one node.
// AccountStatusUnknown is the client's own condition before a valid control
// response has been received; it is never produced by the control server.
type AccountStatus uint8

const (
	AccountStatusUnknown AccountStatus = iota
	AccountStatusNormal
	AccountStatusGrace
	AccountStatusDisabled
)

func (s AccountStatus) String() string {
	switch s {
	case AccountStatusNormal:
		return "normal"
	case AccountStatusGrace:
		return "grace"
	case AccountStatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// StatusRecord keeps the most recent explicit state plus the times of the
// last check, success and failure. A failed query never changes Status.
type StatusRecord struct {
	Status      AccountStatus
	LastCheck   time.Time
	LastSuccess time.Time
	LastFailure time.Time
}

// PolicyStore is per strategy instance. It never shares state with another
// proxy group or a reloaded instance. Node identity is the configured node-id,
// not a proxy name, so several proxy entries for one node share the state.
type PolicyStore struct {
	mu      sync.RWMutex
	records map[string]StatusRecord
}

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{records: map[string]StatusRecord{}}
}

func (p *PolicyStore) Get(nodeID string) StatusRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if record, ok := p.records[nodeID]; ok {
		return record
	}
	return StatusRecord{Status: AccountStatusUnknown}
}

// RecordSuccess applies a valid control response.
func (p *PolicyStore) RecordSuccess(nodeID string, status AccountStatus, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record := p.records[nodeID]
	record.Status = status
	record.LastCheck = at
	record.LastSuccess = at
	p.records[nodeID] = record
}

// RecordFailure preserves the last explicit status and only records the
// failure time. 401/404/429/5xx/timeouts are query failures, not states.
func (p *PolicyStore) RecordFailure(nodeID string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record := p.records[nodeID]
	record.LastCheck = at
	record.LastFailure = at
	p.records[nodeID] = record
}

// AllowsNewBinding reports whether a new website binding may be created on
// this node. Unknown is allowed: the server is the final authority and the
// first startup must not fabricate a quota. Grace and disabled forbid new
// bindings.
func (p *PolicyStore) AllowsNewBinding(nodeID string) bool {
	switch p.Get(nodeID).Status {
	case AccountStatusUnknown, AccountStatusNormal:
		return true
	default:
		return false
	}
}

// AllowsExistingBinding reports whether an already cached binding may still be
// tried. Grace keeps old bindings; the server independently decides whether a
// particular old site is still allowed. Disabled invalidates all bindings on
// that account/node.
func (p *PolicyStore) AllowsExistingBinding(nodeID string) bool {
	return p.Get(nodeID).Status != AccountStatusDisabled
}
