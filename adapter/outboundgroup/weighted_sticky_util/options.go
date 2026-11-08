package weightedsticky

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultWeightedStickyIdleTimeout = 300 * time.Second
	defaultWeightedStickyMaxBindings = 10000

	defaultControlTimeout       = 3 * time.Second
	defaultControlMinInterval   = 30 * time.Second
	defaultControlGraceInterval = 300 * time.Second
)

// ResilienceOptions is the validated `resilience` block. The block is parsed
// strictly; a disabled block must not carry settings that would be silently
// ignored. Health is not configured here: the proxy group's official health
// check is the only health source.
type ResilienceOptions struct {
	Enabled bool
	Control ControlConfig
}

type ControlConfig struct {
	BaseURL       string
	UUID          string // credential; never logged or included in errors
	Timeout       time.Duration
	MinInterval   time.Duration
	GraceInterval time.Duration
}

// Options is the validated form of the `weighted-sticky` block.
// It never carries a country, price or quota role: cache identity comes from
// site-groups and the request identity, health comes from the official proxy
// group check, and quota observations come only from the control endpoint.
type Options struct {
	IdleTimeout time.Duration
	Nodes       []Node
	MaxBindings int
	SiteGroups  []SiteGroup
	Sites       *SiteGroupIndex
	Blacklist   *SiteBlacklistIndex
	Resilience  *ResilienceOptions
}

var weightedStickyOptionKeys = map[string]struct{}{
	"idle-timeout": {},
	"nodes":        {},
	"max-bindings": {},
	"site-groups":  {},
	"resilience":   {},
}

var siteGroupKeys = map[string]struct{}{
	"name":            {},
	"domains":         {},
	"domain-suffixes": {},
}

// ParseOptions validates server ownership independently of optional quota observation.
func ParseOptions(raw map[string]any, staticNames []string, dynamic bool) (*Options, error) {
	config := &Options{IdleTimeout: defaultWeightedStickyIdleTimeout, MaxBindings: defaultWeightedStickyMaxBindings}
	for _, key := range []string{"weights", "default-weight"} {
		if _, ok := raw[key]; ok {
			return nil, fmt.Errorf("weighted-sticky %s was removed; migrate to nodes with server weights and proxy membership", key)
		}
	}
	if err := rejectUnknownKeys(raw, weightedStickyOptionKeys, "weighted-sticky option"); err != nil {
		return nil, err
	}
	var err error
	config.Nodes, err = parseNodes(raw["nodes"], staticNames, dynamic)
	if err != nil {
		return nil, err
	}
	if value, ok := raw["idle-timeout"]; ok {
		config.IdleTimeout, err = strictPositiveSeconds(value, "weighted-sticky idle-timeout")
		if err != nil {
			return nil, err
		}
	}
	if value, ok := raw["max-bindings"]; ok {
		config.MaxBindings, err = strictNonNegativeInt(value, "weighted-sticky max-bindings")
		if err != nil {
			return nil, err
		}
		if config.MaxBindings == 0 {
			return nil, errors.New("weighted-sticky max-bindings must be positive")
		}
	}
	if value, ok := raw["site-groups"]; ok {
		config.SiteGroups, err = parseWeightedStickySiteGroups(value)
		if err != nil {
			return nil, err
		}
	}
	if value, ok := raw["resilience"]; ok {
		config.Resilience, err = parseResilience(value)
		if err != nil {
			return nil, err
		}
	}
	config.Sites, err = NewSiteGroupIndex(config.SiteGroups)
	return config, err
}

func parseWeightedStickySiteGroups(value any) ([]SiteGroup, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("weighted-sticky site-groups must be a list")
	}

	groups := make([]SiteGroup, 0, len(list))
	for i, item := range list {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("weighted-sticky site-groups[%d] must be a mapping", i)
		}
		if err := rejectUnknownKeys(mapping, siteGroupKeys, fmt.Sprintf("weighted-sticky site-groups[%d]", i)); err != nil {
			return nil, err
		}

		name, ok := mapping["name"].(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("weighted-sticky site-groups[%d].name must be a non-empty string", i)
		}

		domains, err := parseDomainList(mapping["domains"], fmt.Sprintf("weighted-sticky site-groups[%d].domains", i))
		if err != nil {
			return nil, err
		}
		suffixes, err := parseDomainList(mapping["domain-suffixes"], fmt.Sprintf("weighted-sticky site-groups[%d].domain-suffixes", i))
		if err != nil {
			return nil, err
		}
		if len(domains) == 0 && len(suffixes) == 0 {
			return nil, fmt.Errorf("weighted-sticky site-groups[%d] (%q) needs at least one domain or domain-suffix", i, name)
		}

		groups = append(groups, SiteGroup{
			Name:     name,
			Domains:  domains,
			Suffixes: suffixes,
		})
	}

	return groups, nil
}

func parseDomainList(value any, field string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of strings", field)
	}

	domains := make([]string, 0, len(list))
	seen := map[string]struct{}{}
	for i, item := range list {
		raw, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", field, i)
		}
		domain, err := normalizeDomain(raw)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, nil
}

func rejectUnknownKeys(mapping map[string]any, allowed map[string]struct{}, field string) error {
	unknown := make([]string, 0)
	for key := range mapping {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s has unknown field %q", field, unknown[0])
}

// strictNonNegativeInt accepts only integer values. Weak decoding is
// deliberately not used: a float, string or bool in a weight field is a
// configuration mistake, not a value to coerce.
func strictNonNegativeInt(value any, field string) (int, error) {
	var number int64
	switch v := value.(type) {
	case int:
		number = int64(v)
	case int8:
		number = int64(v)
	case int16:
		number = int64(v)
	case int32:
		number = int64(v)
	case int64:
		number = v
	case uint:
		if uint64(v) > uint64(math.MaxInt) {
			return 0, fmt.Errorf("%s overflows int", field)
		}
		number = int64(v)
	case uint8:
		number = int64(v)
	case uint16:
		number = int64(v)
	case uint32:
		number = int64(v)
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, fmt.Errorf("%s overflows int", field)
		}
		number = int64(v)
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}

	if number < 0 {
		return 0, fmt.Errorf("%s must not be negative", field)
	}
	if number > int64(math.MaxInt) {
		return 0, fmt.Errorf("%s overflows int", field)
	}
	return int(number), nil
}
