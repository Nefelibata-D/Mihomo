package weightedsticky

import (
	"errors"
	"math"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrNoAvailableCandidates = errors.New("weighted-sticky: no available candidate")
	ErrWeightOverflow        = errors.New("weighted-sticky: weight sum overflow")
)

// SelectServer samples a server once, then samples uniformly within its remaining proxies.
func SelectServer(candidates []C.Proxy, nodes []Node, randIntn func(int) int) (C.Proxy, error) {
	byName := make(map[string]C.Proxy, len(candidates))
	for _, p := range candidates {
		byName[p.Name()] = p
	}
	type pool struct {
		node    Node
		proxies []C.Proxy
	}
	var pools []pool
	total := 0
	for _, node := range nodes {
		item := pool{node: node}
		for _, name := range node.Proxies {
			if p := byName[name]; p != nil {
				item.proxies = append(item.proxies, p)
			}
		}
		if len(item.proxies) > 0 {
			if node.Weight <= 0 {
				return nil, errors.New("node weight must be positive")
			}
			if total > math.MaxInt-node.Weight {
				return nil, ErrWeightOverflow
			}
			total += node.Weight
			pools = append(pools, item)
		}
	}
	if total == 0 {
		return nil, ErrNoAvailableCandidates
	}
	draw := randIntn(total)
	if draw < 0 || draw >= total {
		return nil, errors.New("invalid server random draw")
	}
	for _, p := range pools {
		if draw < p.node.Weight {
			i := randIntn(len(p.proxies))
			if i < 0 || i >= len(p.proxies) {
				return nil, errors.New("invalid proxy random draw")
			}
			return p.proxies[i], nil
		}
		draw -= p.node.Weight
	}
	return nil, ErrNoAvailableCandidates
}

func (s *Strategy) healthyCandidates(candidates []C.Proxy) []C.Proxy {
	var healthy []C.Proxy
	for _, p := range candidates {
		if s.alive(p) {
			healthy = append(healthy, p)
		}
	}
	return healthy
}

func preferNonBlacklisted(candidates []C.Proxy, blocked map[string]struct{}) []C.Proxy {
	var preferred []C.Proxy
	for _, p := range candidates {
		if _, excluded := blocked[p.Name()]; !excluded {
			preferred = append(preferred, p)
		}
	}
	if len(preferred) > 0 {
		return preferred
	}
	return candidates
}
