package weightedsticky

// Providers publish completion only after their concurrent official URL tests have finished.
type healthObserver interface {
	ObserveHealthCheck(func()) func()
	HealthCheckRunning() bool
}

// ObserveHealth reads official URL-specific records; it never probes or writes health itself.
func (s *Strategy) ObserveHealth() {
	if s.validator == nil || s.candidates == nil {
		return
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	for _, provider := range s.providers {
		if observer, ok := provider.(healthObserver); ok && observer.HealthCheckRunning() {
			return
		}
	}
	type result struct {
		count     int
		allFailed bool
	}
	nodes := map[string]result{}
	for _, p := range s.candidates() {
		id := s.nodeID(p)
		if id == "" {
			continue
		}
		r, exists := nodes[id]
		if !exists {
			r.allFailed = true
		}
		r.count++
		if running, ok := p.(interface{ HealthCheckRunningForURL(string) bool }); ok && running.HealthCheckRunningForURL(s.testURL) {
			r.allFailed = false
		}
		state, valid := p.ExtraDelayHistories()[s.testURL]
		if !valid || len(state.History) == 0 || state.Alive {
			r.allFailed = false
		}
		nodes[id] = r
	}
	for id, r := range nodes {
		if r.count > 0 && r.allFailed {
			s.validator.TriggerHealthFailure(id)
		}
	}
}
