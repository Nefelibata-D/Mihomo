package weightedsticky

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// SiteGroup is one explicit business group. Domains are exact
// matches; suffixes cover the named root and its subdomains. The group name is
// the cache identity, so several domains can share one egress.
type SiteGroup struct {
	Name     string
	Domains  []string
	Suffixes []string
}

type siteSuffixRule struct {
	domain string
	group  string
}

// SiteGroupIndex resolves a normalized host to an explicit business group.
// Exact matches win; among suffixes the longest match wins. Conflicts at the
// same priority are rejected when the index is built.
type SiteGroupIndex struct {
	exact    map[string]string
	suffixes []siteSuffixRule
}

func NewSiteGroupIndex(groups []SiteGroup) (*SiteGroupIndex, error) {
	index := &SiteGroupIndex{exact: map[string]string{}}
	names := map[string]struct{}{}
	suffixOwners := map[string]string{}

	for _, group := range groups {
		if strings.TrimSpace(group.Name) == "" {
			return nil, errors.New("weighted-sticky: site group name must not be empty")
		}
		if _, exists := names[group.Name]; exists {
			return nil, fmt.Errorf("weighted-sticky: duplicate site group name %q", group.Name)
		}
		names[group.Name] = struct{}{}

		if len(group.Domains) == 0 && len(group.Suffixes) == 0 {
			return nil, fmt.Errorf("weighted-sticky: site group %q has no domains or domain-suffixes", group.Name)
		}

		seenDomain := map[string]struct{}{}
		for _, raw := range group.Domains {
			domain, err := normalizeDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("weighted-sticky: site group %q: %w", group.Name, err)
			}
			if _, seen := seenDomain[domain]; seen {
				continue
			}
			seenDomain[domain] = struct{}{}

			if owner, exists := index.exact[domain]; exists && owner != group.Name {
				return nil, fmt.Errorf("weighted-sticky: domain %q is listed in both site groups %q and %q", domain, owner, group.Name)
			}
			index.exact[domain] = group.Name
		}

		seenSuffix := map[string]struct{}{}
		for _, raw := range group.Suffixes {
			domain, err := normalizeDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("weighted-sticky: site group %q: %w", group.Name, err)
			}
			if _, seen := seenSuffix[domain]; seen {
				continue
			}
			seenSuffix[domain] = struct{}{}

			if owner, exists := suffixOwners[domain]; exists && owner != group.Name {
				return nil, fmt.Errorf("weighted-sticky: domain-suffix %q is listed in both site groups %q and %q", domain, owner, group.Name)
			}
			suffixOwners[domain] = group.Name
		}
	}

	for domain, group := range suffixOwners {
		index.suffixes = append(index.suffixes, siteSuffixRule{domain: domain, group: group})
	}
	// Longest suffix first, so the most specific business group wins.
	sort.Slice(index.suffixes, func(i, j int) bool {
		if len(index.suffixes[i].domain) != len(index.suffixes[j].domain) {
			return len(index.suffixes[i].domain) > len(index.suffixes[j].domain)
		}
		return index.suffixes[i].domain < index.suffixes[j].domain
	})

	return index, nil
}

func (index *SiteGroupIndex) Match(host string) (string, bool) {
	if index == nil {
		return "", false
	}
	if group, ok := index.exact[host]; ok {
		return group, true
	}
	for _, rule := range index.suffixes {
		if host == rule.domain || strings.HasSuffix(host, "."+rule.domain) {
			return rule.group, true
		}
	}
	return "", false
}

// normalizeDomain lowercases, strips a trailing dot and converts an IDN to its
// ASCII form. Matching is then plain label-boundary comparison.
func normalizeDomain(raw string) (string, error) {
	domain := strings.TrimSpace(raw)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" {
		return "", errors.New("domain must not be empty")
	}
	if strings.ContainsAny(domain, " \t\r\n/\\@") {
		return "", fmt.Errorf("invalid domain %q", raw)
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", raw, err)
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	return ascii, nil
}

func normalizeMetadataHost(host string) (string, error) {
	// A host field never carries brackets, but accepting them here keeps the
	// normalizer usable for literal IPv6 values copied from configuration.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return normalizeDomain(host)
}

func bindingIdentity(metadata *C.Metadata) (string, error) {
	if metadata == nil {
		return "", errors.New("weighted-sticky: cannot build a cache key without metadata")
	}
	if metadata.InUser != "" {
		return "user\x00" + metadata.InUser, nil
	}
	if metadata.SrcIP.IsValid() {
		return "src\x00" + metadata.SrcIP.Unmap().String(), nil
	}
	return "", errors.New("weighted-sticky: no authenticated user or valid source address")
}

func siteBindingKey(metadata *C.Metadata, index *SiteGroupIndex) (string, error) {
	if metadata == nil {
		return "", errors.New("weighted-sticky: cannot build a site key without metadata")
	}

	if metadata.Host != "" {
		host := metadata.Host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			return "ip\x00" + addr.Unmap().String(), nil
		}

		domain, err := normalizeMetadataHost(host)
		if err != nil {
			return "", err
		}
		if group, ok := index.Match(domain); ok {
			return "site\x00" + group, nil
		}

		etld, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			// A host without a derivable eTLD+1 (for example localhost or a
			// public suffix itself) still names a single destination; using the
			// normalized host keeps it isolated instead of merging sites.
			etld = domain
		}
		return "domain\x00" + etld, nil
	}

	if metadata.DstIP.IsValid() {
		return "ip\x00" + metadata.DstIP.Unmap().String(), nil
	}

	return "", errors.New("weighted-sticky: no host or destination address")
}

// BindingKey scopes the website identity to the inbound identity. A user name
// and a source address that happen to be equal remain distinct namespaces.
func BindingKey(metadata *C.Metadata, index *SiteGroupIndex) (string, error) {
	identity, err := bindingIdentity(metadata)
	if err != nil {
		return "", err
	}
	site, err := siteBindingKey(metadata, index)
	if err != nil {
		return "", err
	}
	return identity + "\x00" + site, nil
}

// SiteBlacklistEntry keeps one proxy out of new bindings for the listed
// websites. Domains are exact matches; suffixes cover the named root and its
// subdomains. Several entries may name the same proxy or the same domain.
type SiteBlacklistEntry struct {
	Proxy    string
	Domains  []string
	Suffixes []string
}

type blacklistSuffixRule struct {
	domain  string
	proxies map[string]struct{}
}

// SiteBlacklistIndex resolves the current request host to the set of proxy
// names that the subscription excludes from new bindings for that host.
// Matching is per proxy: an entry never replaces the website cache key.
type SiteBlacklistIndex struct {
	exact    map[string]map[string]struct{}
	suffixes []blacklistSuffixRule
}

func NewSiteBlacklistIndex(entries []SiteBlacklistEntry) (*SiteBlacklistIndex, error) {
	index := &SiteBlacklistIndex{exact: map[string]map[string]struct{}{}}
	suffixProxies := map[string]map[string]struct{}{}

	add := func(target map[string]map[string]struct{}, domain, proxy string) {
		if target[domain] == nil {
			target[domain] = map[string]struct{}{}
		}
		target[domain][proxy] = struct{}{}
	}

	for i, entry := range entries {
		proxy := strings.TrimSpace(entry.Proxy)
		if proxy == "" {
			return nil, fmt.Errorf("weighted-sticky: site-blacklist[%d].proxy must not be empty", i)
		}
		if len(entry.Domains) == 0 && len(entry.Suffixes) == 0 {
			return nil, fmt.Errorf("weighted-sticky: site-blacklist[%d] needs at least one domain or domain-suffix", i)
		}

		seenExact := map[string]struct{}{}
		for _, raw := range entry.Domains {
			domain, err := normalizeDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("weighted-sticky: site-blacklist[%d]: %w", i, err)
			}
			if _, seen := seenExact[domain]; seen {
				continue
			}
			seenExact[domain] = struct{}{}
			add(index.exact, domain, proxy)
		}

		seenSuffix := map[string]struct{}{}
		for _, raw := range entry.Suffixes {
			domain, err := normalizeDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("weighted-sticky: site-blacklist[%d]: %w", i, err)
			}
			if _, seen := seenSuffix[domain]; seen {
				continue
			}
			seenSuffix[domain] = struct{}{}
			add(suffixProxies, domain, proxy)
		}
	}

	for domain, proxies := range suffixProxies {
		index.suffixes = append(index.suffixes, blacklistSuffixRule{domain: domain, proxies: proxies})
	}
	// Longest suffix first is not required for a per-proxy union, but a stable
	// order keeps matching deterministic and easy to inspect.
	sort.Slice(index.suffixes, func(i, j int) bool {
		if len(index.suffixes[i].domain) != len(index.suffixes[j].domain) {
			return len(index.suffixes[i].domain) > len(index.suffixes[j].domain)
		}
		return index.suffixes[i].domain < index.suffixes[j].domain
	})
	return index, nil
}

// Match returns the union of proxies excluded for host. exact and suffix rules
// are both applied; a nil result means no rule matches.
func (index *SiteBlacklistIndex) Match(host string) map[string]struct{} {
	if index == nil || host == "" {
		return nil
	}
	var matches map[string]struct{}
	if proxies, ok := index.exact[host]; ok {
		matches = make(map[string]struct{}, len(proxies))
		for proxy := range proxies {
			matches[proxy] = struct{}{}
		}
	}
	for _, rule := range index.suffixes {
		if host != rule.domain && !strings.HasSuffix(host, "."+rule.domain) {
			continue
		}
		if matches == nil {
			matches = map[string]struct{}{}
		}
		for proxy := range rule.proxies {
			matches[proxy] = struct{}{}
		}
	}
	return matches
}

func (index *SiteBlacklistIndex) Blacklisted(host, proxy string) bool {
	_, ok := index.Match(host)[proxy]
	return ok
}

// siteHost returns the normalized request domain used by the blacklist. IP
// destinations and requests without a host never match a blacklist entry.
func siteHost(metadata *C.Metadata) (string, error) {
	if metadata == nil {
		return "", errors.New("weighted-sticky: cannot resolve a site host without metadata")
	}
	if metadata.Host == "" {
		return "", nil
	}
	host := metadata.Host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", nil
	}
	return normalizeMetadataHost(host)
}

// Site-group and site-blacklist are intentionally separate: site-groups decide
// the cache key, while the blacklist is evaluated per request host. If domains
// sharing one site-group carry different blacklists, the first successful bind
// decides the egress for the group; the subscription author should split such
// domains into separate site-groups when that is not wanted. No second grouping
// or matching language is introduced here.
