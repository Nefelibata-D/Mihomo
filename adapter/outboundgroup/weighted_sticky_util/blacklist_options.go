package weightedsticky

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

type SiteBlacklistEntry struct {
	Proxy        string
	Group        string
	rules        []C.Rule
	providers    []string
	needsProcess bool
}

type SiteBlacklistIndex struct {
	entries   []SiteBlacklistEntry
	providers map[string]P.RuleProvider
	source    *SiteBlacklistIndex
	group     string
}

func (index *SiteBlacklistIndex) ForGroup(name string) *SiteBlacklistIndex {
	if index == nil {
		return nil
	}
	return &SiteBlacklistIndex{source: index, group: name}
}

func ParseSiteBlacklist(value any) ([]SiteBlacklistEntry, *SiteBlacklistIndex, error) {
	if value == nil {
		return nil, nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("site-blacklist must be a list")
	}
	index := &SiteBlacklistIndex{}
	for i, item := range list {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("site-blacklist[%d] must be a mapping", i)
		}
		if err := rejectUnknownKeys(mapping, map[string]struct{}{"proxy": {}, "rules": {}, "group": {}}, fmt.Sprintf("site-blacklist[%d]", i)); err != nil {
			return nil, nil, err
		}
		proxy, ok := mapping["proxy"].(string)
		if !ok || strings.TrimSpace(proxy) == "" {
			return nil, nil, fmt.Errorf("site-blacklist[%d].proxy must be a non-empty string", i)
		}
		lines, ok := mapping["rules"].([]any)
		if !ok || len(lines) == 0 {
			return nil, nil, fmt.Errorf("site-blacklist[%d].rules must be a non-empty list", i)
		}
		entry := SiteBlacklistEntry{Proxy: proxy}
		if raw, exists := mapping["group"]; exists {
			group, ok := raw.(string)
			if !ok || strings.TrimSpace(group) == "" {
				return nil, nil, fmt.Errorf("site-blacklist[%d].group must be a non-empty string", i)
			}
			entry.Group = group
		}
		for j, raw := range lines {
			line, ok := raw.(string)
			if !ok {
				return nil, nil, fmt.Errorf("site-blacklist[%d].rules[%d] must be a string", i, j)
			}
			kind, payload, _, params := RC.ParseRulePayload(line, false)
			if payload == "" || len(params) != 0 {
				return nil, nil, fmt.Errorf("invalid blacklist rule %q", line)
			}
			switch kind {
			case "RULE-SET":
				entry.providers = append(entry.providers, payload)
			case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD":
				rule, err := R.ParseRule(kind, payload, "", nil, nil)
				if err != nil {
					return nil, nil, err
				}
				entry.rules = append(entry.rules, rule)
				switch rule.RuleType() {
				case C.ProcessName, C.ProcessPath, C.ProcessNameRegex, C.ProcessPathRegex, C.ProcessNameWildcard, C.ProcessPathWildcard:
					entry.needsProcess = true
				}
			default:
				return nil, nil, fmt.Errorf("unsupported blacklist rule %q", line)
			}
		}
		index.entries = append(index.entries, entry)
	}
	return index.entries, index, nil
}

func (index *SiteBlacklistIndex) ProviderNames() map[string]bool {
	names := map[string]bool{}
	if index != nil {
		for _, entry := range index.entries {
			for _, name := range entry.providers {
				names[name] = true
			}
		}
	}
	return names
}

func (index *SiteBlacklistIndex) BindProviders(providers map[string]P.RuleProvider) error {
	if index == nil {
		return nil
	}
	for name := range index.ProviderNames() {
		if providers[name] == nil {
			return fmt.Errorf("site-blacklist references unknown rule-set %q", name)
		}
	}
	index.providers = providers
	return nil
}

func (index *SiteBlacklistIndex) Match(metadata *C.Metadata) map[string]struct{} {
	if index == nil || metadata == nil {
		return nil
	}
	host, err := siteHost(metadata)
	if err != nil {
		return nil
	}
	normalized := *metadata
	normalized.Host = host
	normalized.SniffHost = ""
	metadata = &normalized
	matches := map[string]struct{}{}
	source := index
	if index.source != nil {
		source = index.source
	}
	for _, entry := range source.entries {
		if entry.Group != "" && entry.Group != index.group {
			continue
		}
		for _, rule := range entry.rules {
			if matched, _ := rule.Match(metadata, C.RuleMatchHelper{}); matched {
				matches[entry.Proxy] = struct{}{}
				break
			}
		}
		if _, matched := matches[entry.Proxy]; matched {
			continue
		}
		for _, name := range entry.providers {
			if provider := source.providers[name]; provider != nil && provider.Match(metadata, C.RuleMatchHelper{}) {
				matches[entry.Proxy] = struct{}{}
				break
			}
		}
	}
	return matches
}

func (index *SiteBlacklistIndex) Blacklisted(host, proxy string) bool {
	_, ok := index.Match(&C.Metadata{Host: host})[proxy]
	return ok
}

// NeedsProcess checks the current provider strategy after each provider update.
func (index *SiteBlacklistIndex) NeedsProcess() bool {
	if index == nil {
		return false
	}
	source := index
	if index.source != nil {
		source = index.source
	}
	for _, entry := range source.entries {
		if entry.Group != "" && entry.Group != index.group {
			continue
		}
		if entry.needsProcess {
			return true
		}
		for _, name := range entry.providers {
			if provider := source.providers[name]; provider != nil {
				if strategy, ok := provider.Strategy().(interface{ NeedsProcess() bool }); ok && strategy.NeedsProcess() {
					return true
				}
			}
		}
	}
	return false
}
