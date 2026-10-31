package weightedsticky

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
)

const maxControlNodes = 32

// removedResilienceKeys are rejected with an explicit migration message.
// Leaving them in the unknown-key path would make an old configuration look
// like a typo while the removed mechanism silently disappeared.
var removedResilienceKeys = map[string]string{
	"bound-attempts":    "attempts are bounded by the official tunnel retry budget",
	"attempt-timeout":   "each official retry uses the tunnel context; do not set a second per-attempt budget",
	"total-timeout":     "the official tunnel context is the total budget; do not set a second total budget",
	"probe-url":         "custom probe health selection was removed; use the proxy group's official url health check",
	"probe-timeout":     "the custom probe was removed; the official proxy group health check owns its timeout",
	"recovery-interval": "the custom probe recovery loop was removed; the official proxy group health check owns probing",
	"preferred-sites":   "preferred-sites was removed; use site-blacklist to keep a proxy out of new bindings for listed websites",
	"site-blacklist":    "site-blacklist is now a top-level subscription field shared by weighted-sticky groups",
}

var resilienceKeys = map[string]struct{}{
	"enabled": {},
	"control": {},
}

var controlKeys = map[string]struct{}{
	"base-url":       {},
	"uuid":           {},
	"timeout":        {},
	"min-interval":   {},
	"grace-interval": {},
	"node-ids":       {},
}

func parseResilience(value any, staticNames []string, dynamic bool) (*ResilienceOptions, error) {
	mapping, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("weighted-sticky resilience must be a mapping")
	}
	for key, reason := range removedResilienceKeys {
		if _, present := mapping[key]; present {
			return nil, fmt.Errorf("weighted-sticky resilience %s was removed: %s", key, reason)
		}
	}
	if err := rejectUnknownKeys(mapping, resilienceKeys, "weighted-sticky resilience"); err != nil {
		return nil, err
	}

	rawEnabled, ok := mapping["enabled"]
	if !ok {
		return nil, errors.New("weighted-sticky resilience requires an explicit enabled flag")
	}
	enabled, ok := rawEnabled.(bool)
	if !ok {
		return nil, errors.New("weighted-sticky resilience enabled must be a boolean")
	}
	if !enabled {
		if len(mapping) != 1 {
			return nil, errors.New("weighted-sticky resilience with enabled: false must not carry other settings")
		}
		return nil, nil
	}

	options := &ResilienceOptions{Enabled: true}

	controlRaw, ok := mapping["control"]
	if !ok {
		return nil, errors.New("weighted-sticky resilience requires a control block")
	}
	control, err := parseControlConfig(controlRaw, staticNames, dynamic)
	if err != nil {
		return nil, err
	}
	options.Control = control

	return options, nil
}

func parseControlConfig(value any, staticNames []string, dynamic bool) (ControlConfig, error) {
	mapping, ok := value.(map[string]any)
	if !ok {
		return ControlConfig{}, errors.New("weighted-sticky resilience control must be a mapping")
	}
	if err := rejectUnknownKeys(mapping, controlKeys, "weighted-sticky resilience control"); err != nil {
		return ControlConfig{}, err
	}
	config := ControlConfig{
		Timeout:       defaultControlTimeout,
		MinInterval:   defaultControlMinInterval,
		GraceInterval: defaultControlGraceInterval,
	}

	rawBaseURL, ok := mapping["base-url"].(string)
	if !ok || strings.TrimSpace(rawBaseURL) == "" {
		return ControlConfig{}, errors.New("weighted-sticky resilience control base-url must be a non-empty string")
	}
	if _, err := validateControlBaseURL(rawBaseURL); err != nil {
		return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control base-url: %w", err)
	}
	config.BaseURL = rawBaseURL

	rawUUID, ok := mapping["uuid"].(string)
	if !ok || strings.TrimSpace(rawUUID) == "" {
		return ControlConfig{}, errors.New("weighted-sticky resilience control uuid must be a non-empty string")
	}
	if _, err := uuid.FromString(rawUUID); err != nil {
		// Never echo the credential in an error.
		return ControlConfig{}, errors.New("weighted-sticky resilience control uuid is not a valid UUID")
	}
	config.UUID = rawUUID

	if value, ok := mapping["timeout"]; ok {
		timeout, err := strictPositiveSeconds(value, "weighted-sticky resilience control timeout")
		if err != nil {
			return ControlConfig{}, err
		}
		config.Timeout = timeout
	}
	if value, ok := mapping["min-interval"]; ok {
		interval, err := strictPositiveSeconds(value, "weighted-sticky resilience control min-interval")
		if err != nil {
			return ControlConfig{}, err
		}
		config.MinInterval = interval
	}
	if value, ok := mapping["grace-interval"]; ok {
		interval, err := strictPositiveSeconds(value, "weighted-sticky resilience control grace-interval")
		if err != nil {
			return ControlConfig{}, err
		}
		config.GraceInterval = interval
	}

	rawNodes, ok := mapping["node-ids"].(map[string]any)
	if !ok || len(rawNodes) == 0 {
		return ControlConfig{}, errors.New("weighted-sticky resilience control node-ids must be a non-empty mapping")
	}
	nodeIDs := make(map[string]string, len(rawNodes))
	for name, rawNode := range rawNodes {
		if strings.TrimSpace(name) == "" {
			return ControlConfig{}, errors.New("weighted-sticky resilience control node-ids contains an empty proxy name")
		}
		node, ok := rawNode.(string)
		if !ok || strings.TrimSpace(node) == "" {
			return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control node-ids[%q] must be a non-empty string", name)
		}
		if strings.ContainsAny(node, "/ \t\r\n") {
			return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control node-ids[%q] contains an invalid node id", name)
		}
		nodeIDs[name] = node
	}
	// The experiment supports at most 32 servers. Several proxy names (aliases)
	// may map to one node, so the limit counts distinct node ids, not names.
	distinctNodes := make(map[string]struct{}, len(nodeIDs))
	for _, node := range nodeIDs {
		distinctNodes[node] = struct{}{}
	}
	if len(distinctNodes) > maxControlNodes {
		return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control node-ids has %d distinct nodes; at most %d are supported", len(distinctNodes), maxControlNodes)
	}

	static := make(map[string]struct{}, len(staticNames))
	for _, name := range staticNames {
		static[name] = struct{}{}
	}
	for _, name := range staticNames {
		if _, ok := nodeIDs[name]; !ok {
			return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control node-ids is missing candidate %q", name)
		}
	}
	for name := range nodeIDs {
		if _, ok := static[name]; ok {
			continue
		}
		if !dynamic {
			return ControlConfig{}, fmt.Errorf("weighted-sticky resilience control node-ids references unknown proxy %q", name)
		}
		log.Debugln("weighted-sticky: control node-ids entry %q has no candidate yet; it will apply if the provider adds it", name)
	}
	config.NodeIDs = nodeIDs
	return config, nil
}

func strictPositiveSeconds(value any, field string) (time.Duration, error) {
	seconds, err := strictNonNegativeInt(value, field)
	if err != nil {
		return 0, err
	}
	if seconds == 0 {
		return 0, fmt.Errorf("%s must be a positive number of seconds", field)
	}
	// Checked before the multiplication: an overflowing conversion would
	// otherwise produce a negative duration and a busy timer.
	if int64(seconds) > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("%s overflows time.Duration", field)
	}
	return time.Duration(seconds) * time.Second, nil
}

// validateControlBaseURL enforces the management address shape shared by the
// parser and the client. Credentials in the URL and query/fragment are
// rejected so they cannot leak into logs or requests.
func validateControlBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("has no host")
	}
	if parsed.User != nil {
		return nil, errors.New("must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("must not contain query or fragment")
	}
	return parsed, nil
}
