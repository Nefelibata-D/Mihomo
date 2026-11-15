package weightedsticky

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	"strconv"
	"strings"
)

type StickyRules []stickyRule
type stickyRule struct {
	rule         C.Rule
	providerName string
	provider     P.RuleProvider
	policy       bindingPolicy
}

func ParseSiteSticky(value any) (map[string]StickyRules, error) {
	if value == nil {
		return nil, nil
	}
	groups := make(map[string]StickyRules)
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("site-sticky must be a list")
	}

	for i, item := range list {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("site-sticky[%d] must be a mapping", i)
		}
		if err := rejectUnknownKeys(mapping, map[string]struct{}{"rules": {}, "group": {}}, fmt.Sprintf("site-sticky[%d]", i)); err != nil {
			return nil, err
		}
		group, ok := mapping["group"].(string)
		if !ok || strings.TrimSpace(group) == "" {
			return nil, fmt.Errorf("site-sticky[%d].group must be a non-empty string", i)
		}
		if _, exists := groups[group]; exists {
			return nil, fmt.Errorf("duplicate site-sticky group %q", group)
		}

		lines, ok := mapping["rules"].([]any)
		if !ok || len(lines) == 0 {
			return nil, fmt.Errorf("site-sticky[%d].rules must be a non-empty list", i)
		}
		for j, raw := range lines {
			line, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("site-sticky[%d].rules[%d] must be a string", i, j)
			}
			ruleLine, policy, err := parseStickyRule(line)
			entry := stickyRule{policy: policy}
			if err == nil {
				err = entry.compile(ruleLine)
			}
			if err != nil {
				return nil, fmt.Errorf("site-sticky[%d].rules[%d]: %w", i, j, err)
			}
			groups[group] = append(groups[group], entry)
		}
	}
	return groups, nil
}
func (r *stickyRule) compile(line string) error {
	kind, payload, _, params := RC.ParseRulePayload(line, false)
	if payload == "" || len(params) != 0 {
		return fmt.Errorf("invalid site-sticky rule %q", line)
	}
	switch kind {
	case "RULE-SET":
		r.providerName = payload
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD":
		rule, err := R.ParseRule(kind, payload, "", nil, nil)
		if err != nil {
			return err
		}
		r.rule = rule
	default:
		return fmt.Errorf("unsupported site-sticky rule %q", line)
	}
	return nil
}
func (rules StickyRules) ProviderNames(names map[string]bool) {
	for _, r := range rules {
		if r.providerName != "" {
			names[r.providerName] = true
		}
	}
}
func (rules StickyRules) BindProviders(providers map[string]P.RuleProvider) error {
	for i := range rules {
		r := &rules[i]
		if r.providerName != "" {
			r.provider = providers[r.providerName]
			if r.provider == nil {
				return fmt.Errorf("site-sticky references unknown rule-set %q", r.providerName)
			}
		}
	}
	return nil
}
func (rules StickyRules) NeedsProcess() bool {
	for _, r := range rules {
		if r.rule != nil {
			switch r.rule.RuleType() {
			case C.ProcessName, C.ProcessPath, C.ProcessNameRegex, C.ProcessPathRegex, C.ProcessNameWildcard, C.ProcessPathWildcard:
				return true
			}
		}
		if r.provider != nil {
			if s, ok := r.provider.Strategy().(interface{ NeedsProcess() bool }); ok && s.NeedsProcess() {
				return true
			}
		}
	}
	return false
}
func (rules StickyRules) stickyPolicy(metadata *C.Metadata) bindingPolicy {
	if len(rules) == 0 {
		return bindingPolicy{}
	}
	host, err := siteHost(metadata)
	if err != nil {
		return bindingPolicy{}
	}
	normalized := *metadata
	normalized.Host = host
	normalized.SniffHost = ""
	for _, r := range rules {
		if r.rule != nil {
			if ok, _ := r.rule.Match(&normalized, C.RuleMatchHelper{}); ok {
				return r.policy
			}
		}
		if r.provider != nil && r.provider.Match(&normalized, C.RuleMatchHelper{}) {
			return r.policy
		}
	}
	return bindingPolicy{}
}
func parseStickyRule(line string) (string, bindingPolicy, error) {
	var policy bindingPolicy
	body, renew, ok := splitLast(line)
	rule, seconds, ok2 := splitLast(body)
	if !ok || !ok2 {
		return "", policy, fmt.Errorf("expected TYPE,payload,seconds,auto-renew")
	}
	n, err := strconv.Atoi(seconds)
	if err != nil {
		return "", policy, fmt.Errorf("invalid seconds %q", seconds)
	}
	policy.timeout, err = strictPositiveSeconds(n, "site-sticky timeout")
	if err != nil {
		return "", policy, err
	}
	switch renew {
	case "false":
		policy.fixed = true
	case "true":
	default:
		return "", policy, fmt.Errorf("auto-renew must be true or false")
	}
	return rule, policy, nil
}
func splitLast(s string) (string, string, bool) {
	i := strings.LastIndexByte(s, ',')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}
