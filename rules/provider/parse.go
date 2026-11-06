package provider

import (
	"fmt"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

type ruleProviderSchema struct {
	Type         string              `provider:"type"`
	Behavior     string              `provider:"behavior"`
	Path         string              `provider:"path,omitempty"`
	URL          string              `provider:"url,omitempty"`
	Proxy        string              `provider:"proxy,omitempty"`
	Format       string              `provider:"format,omitempty"`
	Interval     int                 `provider:"interval,omitempty"`
	SizeLimit    int64               `provider:"size-limit,omitempty"`
	Payload      []string            `provider:"payload,omitempty"`
	Header       map[string][]string `provider:"header,omitempty"`
	PathInBundle string              `provider:"path-in-bundle,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]any, parse common.ParseRuleFunc, makeBundleFile func(pathInBundle string) resource.BundleFile, domainOnly ...bool) (P.RuleProvider, error) {
	schema := &ruleProviderSchema{}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}
	behavior, err := P.ParseBehavior(schema.Behavior)
	if err != nil {
		return nil, err
	}
	format, err := P.ParseRuleFormat(schema.Format)
	if err != nil {
		return nil, err
	}

	strict := len(domainOnly) > 0 && domainOnly[0]
	if strict && (behavior != P.Classical || format == P.MrsRule) {
		return nil, fmt.Errorf("blacklist rule-set %s requires classical yaml or text", name)
	}
	if strict {
		strategy := NewClassicalStrategy(parse)
		strategy.domainOnly = true
		rulesParseInline(schema.Payload, strategy)
		if strategy.err != nil {
			return nil, strategy.err
		}
	}
	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		vehicle = resource.NewFileVehicle(path)
	case "http":
		path := C.Path.GetPathByHash("rules", schema.URL)
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
		}
		vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.Proxy, schema.Header, resource.DefaultHttpTimeout, schema.SizeLimit)
	case "inline":
		return NewInlineProvider(name, behavior, schema.Payload, parse, strict), nil
	default:
		return nil, fmt.Errorf("unsupported vehicle type: %s", schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second

	return NewRuleSetProvider(name, behavior, format, interval, vehicle, schema.Payload, makeBundleFile(schema.PathInBundle), parse, strict), nil
}
