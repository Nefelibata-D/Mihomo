package weightedsticky

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const blacklistNameToken = `\s*(?:"(?:\\.|[^"\\])*"|[^,"\[\]\r\n]+)\s*`

var blacklistLinePattern = regexp.MustCompile(`^(.*),\s*\[((?:` + blacklistNameToken + `(?:,` + blacklistNameToken + `)*)?)\]\s*$`)
var blacklistNamesPattern = regexp.MustCompile(blacklistNameToken)

func ParseBlacklistRule(line string) (string, []string, error) {
	parts := blacklistLinePattern.FindStringSubmatch(line)
	if parts == nil || strings.ContainsAny(line, "\r\n") {
		return "", nil, fmt.Errorf("blacklist rule must be TYPE,payload,[proxy names]: %q", line)
	}
	names := []string{}
	seen := map[string]bool{}
	for _, token := range blacklistNamesPattern.FindAllString(parts[2], -1) {
		name := strings.TrimSpace(token)
		if strings.HasPrefix(name, `"`) {
			if err := json.Unmarshal([]byte(name), &name); err != nil {
				return "", nil, fmt.Errorf("invalid blacklist proxy name: %w", err)
			}
		}
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n") || seen[name] {
			return "", nil, fmt.Errorf("empty or duplicate blacklist proxy name: %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return strings.TrimSpace(parts[1]), names, nil
}
