package weightedsticky

import (
	"errors"
	"fmt"
	"strings"
)

var siteBlacklistKeys = map[string]struct{}{
	"domains":         {},
	"domain-suffixes": {},
	"proxy":           {},
}

// ParseSiteBlacklist parses the subscription-wide rules once. Every group
// explicitly using weighted-sticky receives the same immutable index.
func ParseSiteBlacklist(value any) ([]SiteBlacklistEntry, *SiteBlacklistIndex, error) {
	if value == nil {
		return nil, nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, nil, errors.New("site-blacklist must be a list")
	}

	entries := make([]SiteBlacklistEntry, 0, len(list))
	for i, item := range list {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("site-blacklist[%d] must be a mapping", i)
		}
		if err := rejectUnknownKeys(mapping, siteBlacklistKeys, fmt.Sprintf("site-blacklist[%d]", i)); err != nil {
			return nil, nil, err
		}
		proxy, ok := mapping["proxy"].(string)
		if !ok || strings.TrimSpace(proxy) == "" {
			return nil, nil, fmt.Errorf("site-blacklist[%d].proxy must be a non-empty string", i)
		}
		domains, err := parseDomainList(mapping["domains"], fmt.Sprintf("site-blacklist[%d].domains", i))
		if err != nil {
			return nil, nil, err
		}
		suffixes, err := parseDomainList(mapping["domain-suffixes"], fmt.Sprintf("site-blacklist[%d].domain-suffixes", i))
		if err != nil {
			return nil, nil, err
		}
		if len(domains) == 0 && len(suffixes) == 0 {
			return nil, nil, fmt.Errorf("site-blacklist[%d] needs at least one domain or domain-suffix", i)
		}
		entries = append(entries, SiteBlacklistEntry{Proxy: proxy, Domains: domains, Suffixes: suffixes})
	}
	index, err := NewSiteBlacklistIndex(entries)
	return entries, index, err
}
