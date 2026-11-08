package weightedsticky

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

const maxServers = 32

type Node struct {
	Name    string   `json:"name"`
	ID      string   `json:"id"`
	Weight  int      `json:"weight"`
	Proxies []string `json:"proxies"`
}

func parseNodes(value any, names []string, dynamic bool) ([]Node, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, errors.New("weighted-sticky nodes must be a non-empty list")
	}
	if len(list) > maxServers {
		return nil, fmt.Errorf("weighted-sticky supports at most %d servers", maxServers)
	}
	ids, owners := map[string]bool{}, map[string]bool{}
	known := map[string]bool{}
	for _, name := range names {
		if known[name] {
			return nil, fmt.Errorf("duplicate group proxy %q", name)
		}
		known[name] = true
	}
	nodes := make([]Node, 0, len(list))
	total := 0
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("nodes[%d] must be a mapping", i)
		}
		if err := rejectUnknownKeys(m, map[string]struct{}{"name": {}, "id": {}, "weight": {}, "proxies": {}}, "node"); err != nil {
			return nil, err
		}
		name, _ := m["name"].(string)
		id, _ := m["id"].(string)
		if strings.TrimSpace(name) == "" || id == "" || strings.ContainsAny(id, "/ \t\r\n") || ids[id] {
			return nil, fmt.Errorf("nodes[%d] requires a name and a unique valid id", i)
		}
		w, err := strictNonNegativeInt(m["weight"], "node weight")
		if err != nil {
			return nil, err
		}
		if w == 0 {
			return nil, errors.New("node weight must be positive")
		}
		if total > math.MaxInt-w {
			return nil, ErrWeightOverflow
		}
		total += w
		members, ok := m["proxies"].([]any)
		if !ok || len(members) == 0 {
			return nil, fmt.Errorf("node %q requires proxies", id)
		}
		node := Node{Name: name, ID: id, Weight: w}
		for _, v := range members {
			p, ok := v.(string)
			if !ok || strings.TrimSpace(p) == "" || owners[p] || (!dynamic && !known[p]) {
				return nil, fmt.Errorf("node %q has duplicate, unknown or invalid proxy %v", id, v)
			}
			owners[p] = true
			node.Proxies = append(node.Proxies, p)
		}
		ids[id] = true
		nodes = append(nodes, node)
	}
	for _, name := range names {
		if !owners[name] {
			return nil, fmt.Errorf("weighted-sticky nodes missing proxy %q", name)
		}
	}
	return nodes, nil
}
