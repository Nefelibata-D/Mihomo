package weightedsticky

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// Timer and Clock keep the validator's scheduling testable with a virtual
// clock. The production implementation wraps time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer {
	return &realTimer{timer: time.NewTimer(d)}
}

type realTimer struct {
	timer *time.Timer
}

func (t *realTimer) C() <-chan time.Time { return t.timer.C }
func (t *realTimer) Stop()               { t.timer.Stop() }

// StatusChecker is the small surface the validator needs. The production
// implementation is *ControlClient.
type StatusChecker interface {
	Check(ctx context.Context, nodeID string) (AccountStatus, error)
}

type ValidatorOptions struct {
	Checker        StatusChecker
	Store          *PolicyStore
	NodeIDs        []string
	MinInterval    time.Duration
	GraceInterval  time.Duration
	Clock          Clock
	OnStatusChange func(nodeID string, from, to AccountStatus)
}

type triggerRequest struct {
	node string
}

type checkResult struct {
	node   string
	status AccountStatus
	err    error
}

type timerEvent struct {
	node string
	due  time.Time
}

// stoppableTimer closes a stop channel when it is replaced, so the forwarding
// goroutine of a superseded timer does not stay blocked until Close.
type stoppableTimer struct {
	Timer
	stop chan struct{}
	once sync.Once
}

func newStoppableTimer(timer Timer) *stoppableTimer {
	return &stoppableTimer{Timer: timer, stop: make(chan struct{})}
}

func (t *stoppableTimer) Stop() {
	t.once.Do(func() {
		t.Timer.Stop()
		close(t.stop)
	})
}

// Validator owns all status-query scheduling for one strategy instance.
//
// Rules implemented here:
//   - one check per node in flight; triggers while in flight are dropped;
//   - normal/unknown nodes are queried only on load and on business failure,
//     rate-limited by MinInterval;
//   - grace nodes are queried every GraceInterval, including without traffic;
//   - disabled nodes stop periodic queries until the instance is reloaded;
//   - failed queries keep the last explicit status;
//   - no missed period is backfilled: each result schedules at most one next
//     timer, from the time of that result.
type Validator struct {
	checker        StatusChecker
	store          *PolicyStore
	nodeIDs        []string
	minInterval    time.Duration
	graceInterval  time.Duration
	clock          Clock
	onStatusChange func(nodeID string, from, to AccountStatus)

	triggers chan triggerRequest
	queued   map[string]struct{}
	known    map[string]struct{}
	done     chan struct{}

	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	started   bool
	closed    bool
	closeOnce sync.Once
}

func NewValidator(options ValidatorOptions) (*Validator, error) {
	if options.Checker == nil {
		return nil, errors.New("weighted-sticky: validator checker is nil")
	}
	if options.Store == nil {
		return nil, errors.New("weighted-sticky: validator store is nil")
	}
	if len(options.NodeIDs) == 0 {
		return nil, errors.New("weighted-sticky: validator has no node ids")
	}
	if options.MinInterval <= 0 || options.GraceInterval <= 0 {
		return nil, errors.New("weighted-sticky: validator intervals must be positive")
	}
	clock := options.Clock
	if clock == nil {
		clock = realClock{}
	}

	seen := make(map[string]struct{}, len(options.NodeIDs))
	nodes := make([]string, 0, len(options.NodeIDs))
	for _, node := range options.NodeIDs {
		if node == "" {
			return nil, errors.New("weighted-sticky: validator node id is empty")
		}
		if _, exists := seen[node]; exists {
			continue
		}
		seen[node] = struct{}{}
		nodes = append(nodes, node)
	}

	ctx, cancel := context.WithCancel(context.Background())
	v := &Validator{
		checker:        options.Checker,
		store:          options.Store,
		nodeIDs:        nodes,
		minInterval:    options.MinInterval,
		graceInterval:  options.GraceInterval,
		clock:          clock,
		onStatusChange: options.OnStatusChange,
		triggers:       make(chan triggerRequest, len(nodes)),
		queued:         make(map[string]struct{}, len(nodes)),
		known:          seen,
		done:           make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}
	return v, nil
}

// Start begins the startup check and all later scheduling. It is idempotent,
// and a validator closed before Start never starts.
func (v *Validator) Start() {
	v.mu.Lock()
	if v.started || v.closed {
		v.mu.Unlock()
		return
	}
	v.started = true
	ctx := v.ctx
	v.mu.Unlock()
	go v.loop(ctx)
}

// TriggerFailure reports a business dial failure. It never queues a delayed
// task: if the validator is not running, the node is unknown or already
// queued, a check is in flight, the node is disabled/grace, or the minimum
// interval has not elapsed, the trigger is dropped.
func (v *Validator) TriggerFailure(nodeID string) {
	if nodeID == "" {
		return
	}
	v.mu.Lock()
	if !v.started || v.closed {
		v.mu.Unlock()
		return
	}
	if _, known := v.known[nodeID]; !known {
		v.mu.Unlock()
		return
	}
	if _, queued := v.queued[nodeID]; queued {
		v.mu.Unlock()
		return
	}
	v.queued[nodeID] = struct{}{}
	// One queued request per known node keeps the channel within its capacity.
	v.triggers <- triggerRequest{node: nodeID}
	v.mu.Unlock()
}

// Close cancels all timers and in-flight queries. Results from a cancelled
// instance are never delivered to another instance because stores are
// per-instance and the loop is gone.
func (v *Validator) Close() {
	v.closeOnce.Do(func() {
		v.mu.Lock()
		started := v.started
		v.closed = true
		v.mu.Unlock()
		v.cancel()
		if started {
			<-v.done
		}
		if closer, ok := v.checker.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	})
}

func (v *Validator) loop(ctx context.Context) {
	defer close(v.done)
	if ctx.Err() != nil {
		return
	}

	inflight := make(map[string]bool, len(v.nodeIDs))
	lastCheck := make(map[string]time.Time, len(v.nodeIDs))
	timers := make(map[string]*stoppableTimer, len(v.nodeIDs))
	dueAt := make(map[string]time.Time, len(v.nodeIDs))
	results := make(chan checkResult, len(v.nodeIDs))
	events := make(chan timerEvent, len(v.nodeIDs))

	stopAll := func() {
		for node, timer := range timers {
			timer.Stop()
			delete(timers, node)
			delete(dueAt, node)
		}
	}
	defer stopAll()

	schedule := func(node string, delay time.Duration) {
		if timer, ok := timers[node]; ok {
			timer.Stop()
		}
		now := v.clock.Now()
		due := now.Add(delay)
		timer := newStoppableTimer(v.clock.NewTimer(delay))
		timers[node] = timer
		dueAt[node] = due
		go func() {
			select {
			case <-timer.C():
				select {
				case events <- timerEvent{node: node, due: due}:
				case <-ctx.Done():
				}
			case <-timer.stop:
			case <-ctx.Done():
			}
		}()
	}

	startCheck := func(node string) {
		if ctx.Err() != nil {
			return
		}
		inflight[node] = true
		lastCheck[node] = v.clock.Now()
		go func() {
			status, err := v.checker.Check(ctx, node)
			select {
			case results <- checkResult{node: node, status: status, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	// Loading the strategy is the first validation event, regardless of the
	// minimum interval.
	for _, node := range v.nodeIDs {
		startCheck(node)
	}

	for {
		select {
		case <-ctx.Done():
			return

		case result := <-results:
			delete(inflight, result.node)
			before := v.store.Get(result.node).Status
			now := v.clock.Now()
			if result.err != nil {
				log.Debugln("weighted-sticky: status query for node %s failed: %v", result.node, result.err)
				v.store.RecordFailure(result.node, now)
			} else {
				v.store.RecordSuccess(result.node, result.status, now)
				if v.onStatusChange != nil && before != result.status {
					v.onStatusChange(result.node, before, result.status)
				}
			}
			current := v.store.Get(result.node).Status
			if current == AccountStatusGrace {
				schedule(result.node, v.graceInterval)
			} else if timer, ok := timers[result.node]; ok {
				timer.Stop()
				delete(timers, result.node)
				delete(dueAt, result.node)
			}

		case request := <-v.triggers:
			v.mu.Lock()
			delete(v.queued, request.node)
			v.mu.Unlock()
			node := request.node
			if inflight[node] {
				continue
			}
			status := v.store.Get(node).Status
			switch status {
			case AccountStatusDisabled, AccountStatusGrace:
				// Disabled has no periodic queries; grace has its own
				// schedule and must not accumulate failure triggers.
				continue
			}
			if v.clock.Now().Sub(lastCheck[node]) < v.minInterval {
				continue
			}
			startCheck(node)

		case event := <-events:
			due, ok := dueAt[event.node]
			if !ok || !due.Equal(event.due) {
				continue
			}
			delete(timers, event.node)
			delete(dueAt, event.node)
			if inflight[event.node] {
				continue
			}
			startCheck(event.node)
		}
	}
}
