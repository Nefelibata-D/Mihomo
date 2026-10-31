package weightedsticky

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	defaultWeightedStickyIdleTimeout = 300 * time.Second
	defaultWeightedStickyWeight      = 1
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
	NodeIDs       map[string]string
}

// Options is the validated form of the `weighted-sticky` block.
// It never carries a country, price or quota role: cache identity comes from
// site-groups and the request identity, health comes from the official proxy
// group check, and account admission comes only from the control endpoint.
type Options struct {
	IdleTimeout   time.Duration
	DefaultWeight int
	Weights       map[string]int
	MaxBindings   int
	SiteGroups    []SiteGroup
	Sites         *SiteGroupIndex
	Blacklist     *SiteBlacklistIndex
	Resilience    *ResilienceOptions
}

var weightedStickyOptionKeys = map[string]struct{}{
	"idle-timeout":   {},
	"default-weight": {},
	"weights":        {},
	"max-bindings":   {},
	"site-groups":    {},
	"resilience":     {},
}

var siteGroupKeys = map[string]struct{}{
	"name":            {},
	"domains":         {},
	"domain-suffixes": {},
}

// ParseOptions validates the raw block. Omitted values take the
// documented defaults. Unknown keys are errors: a typo must not silently
// produce a different strategy. staticNames are the node names visible from
// static `proxies`; dynamic reports whether a `use` provider can add names
// later, in which case an unmatched weight is only a diagnostic.
func ParseOptions(raw map[string]any, staticNames []string, dynamic bool) (*Options, error) {
	config := &Options{
		IdleTimeout:   defaultWeightedStickyIdleTimeout,
		DefaultWeight: defaultWeightedStickyWeight,
		Weights:       map[string]int{},
		MaxBindings:   defaultWeightedStickyMaxBindings,
	}

	if raw != nil {
		if err := rejectUnknownKeys(raw, weightedStickyOptionKeys, "weighted-sticky option"); err != nil {
			return nil, err
		}

		if value, ok := raw["idle-timeout"]; ok {
			timeout, err := strictPositiveSeconds(value, "weighted-sticky idle-timeout")
			if err != nil {
				return nil, err
			}
			config.IdleTimeout = timeout
		}

		if value, ok := raw["default-weight"]; ok {
			weight, err := strictNonNegativeInt(value, "weighted-sticky default-weight")
			if err != nil {
				return nil, err
			}
			config.DefaultWeight = weight
		}

		if value, ok := raw["max-bindings"]; ok {
			maxBindings, err := strictNonNegativeInt(value, "weighted-sticky max-bindings")
			if err != nil {
				return nil, err
			}
			if maxBindings == 0 {
				return nil, errors.New("weighted-sticky max-bindings must be positive")
			}
			config.MaxBindings = maxBindings
		}

		if value, ok := raw["weights"]; ok {
			mapping, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("weighted-sticky weights must be a mapping of node name to integer")
			}
			for name, rawWeight := range mapping {
				if strings.TrimSpace(name) == "" {
					return nil, errors.New("weighted-sticky weights contains an empty node name")
				}
				weight, err := strictNonNegativeInt(rawWeight, fmt.Sprintf("weighted-sticky weights[%q]", name))
				if err != nil {
					return nil, err
				}
				config.Weights[name] = weight
			}
		}

		if value, ok := raw["site-groups"]; ok {
			groups, err := parseWeightedStickySiteGroups(value)
			if err != nil {
				return nil, err
			}
			config.SiteGroups = groups
		}

		if value, ok := raw["resilience"]; ok {
			resilience, err := parseResilience(value, staticNames, dynamic)
			if err != nil {
				return nil, err
			}
			config.Resilience = resilience
		}
	}

	if config.DefaultWeight == 0 {
		positive := false
		for _, weight := range config.Weights {
			if weight > 0 {
				positive = true
				break
			}
		}
		if !positive {
			return nil, errors.New("weighted-sticky: every weight is zero, no candidate could ever be selected")
		}
	}

	if !dynamic {
		known := make(map[string]struct{}, len(staticNames))
		for _, name := range staticNames {
			known[name] = struct{}{}
		}
		names := make([]string, 0, len(config.Weights))
		for name := range config.Weights {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if _, ok := known[name]; !ok {
				return nil, fmt.Errorf("weighted-sticky weights references unknown proxy %q", name)
			}
		}

		// With static candidates the whole weight sum is known at load time;
		// report overflow as a configuration error rather than at first dial.
		var total uint64
		for name := range known {
			weight := config.DefaultWeight
			if configured, ok := config.Weights[name]; ok {
				weight = configured
			}
			if total > uint64(math.MaxInt)-uint64(weight) {
				return nil, ErrWeightOverflow
			}
			total += uint64(weight)
		}
		// A non-zero default weight does not help when every actual static
		// candidate overrides itself to zero: no candidate could be selected.
		if len(known) > 0 && total == 0 {
			return nil, errors.New("weighted-sticky: every weight is zero, no candidate could ever be selected")
		}
	} else {
		known := make(map[string]struct{}, len(staticNames))
		for _, name := range staticNames {
			known[name] = struct{}{}
		}
		for name := range config.Weights {
			if _, ok := known[name]; !ok {
				log.Debugln("weighted-sticky: weights entry %q has no candidate yet; it will apply if the provider adds it", name)
			}
		}
	}

	index, err := NewSiteGroupIndex(config.SiteGroups)
	if err != nil {
		return nil, err
	}
	config.Sites = index

	return config, nil
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
