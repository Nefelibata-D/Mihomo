package weightedsticky

import (
	"errors"
	"fmt"
	"math"

	C "github.com/metacubex/mihomo/constant"
)

var (
	// ErrNoAvailableCandidates reports that no candidate has positive weight
	// after health and account filtering. The strategy must fail the dial
	// instead of falling back to the first candidate or to DIRECT.
	ErrNoAvailableCandidates = errors.New("weighted-sticky: no available candidate")

	// ErrWeightOverflow reports a weight sum that cannot be represented by the
	// random draw and the cumulative interval.
	ErrWeightOverflow = errors.New("weighted-sticky: weight sum overflow")
)

type weightedCandidate struct {
	proxy  C.Proxy
	weight uint64
}

// SelectCandidate performs standard cumulative weight sampling over
// candidates that have already passed health and account filtering. Weights
// are looked up by the final candidate name, so reordering the candidate list
// does not move a weight to a different node. A zero weight keeps an existing
// binding but never participates in a new draw.
func SelectCandidate(candidates []C.Proxy, weights map[string]int, defaultWeight int, randIntn func(int) int) (C.Proxy, error) {
	if defaultWeight < 0 {
		return nil, fmt.Errorf("weighted-sticky: default-weight must not be negative: %d", defaultWeight)
	}
	if randIntn == nil {
		return nil, errors.New("weighted-sticky: nil random source")
	}

	items := make([]weightedCandidate, 0, len(candidates))
	var total uint64
	for _, proxy := range candidates {
		weight, ok := weights[proxy.Name()]
		if !ok {
			weight = defaultWeight
		}
		if weight < 0 {
			return nil, fmt.Errorf("weighted-sticky: weight of %q must not be negative: %d", proxy.Name(), weight)
		}
		if weight == 0 {
			continue
		}
		if total > uint64(math.MaxInt)-uint64(weight) {
			return nil, ErrWeightOverflow
		}
		total += uint64(weight)
		items = append(items, weightedCandidate{proxy: proxy, weight: uint64(weight)})
	}

	if total == 0 {
		return nil, ErrNoAvailableCandidates
	}

	draw := randIntn(int(total))
	if draw < 0 || uint64(draw) >= total {
		return nil, fmt.Errorf("weighted-sticky: random draw %d outside [0,%d)", draw, total)
	}

	remaining := uint64(draw)
	for _, item := range items {
		if remaining < item.weight {
			return item.proxy, nil
		}
		remaining -= item.weight
	}

	return nil, ErrNoAvailableCandidates
}
