package provider

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
)

type classicalStrategy struct {
	rules      []C.Rule
	count      int
	domainOnly bool
	err        error
	parse      common.ParseRuleFunc
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	for _, rule := range c.rules {
		if m, _ := rule.Match(metadata, helper); m {
			return true
		}
	}

	return false
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) Reset() {
	c.err = nil
	c.rules = nil
	c.count = 0
}

func (c *classicalStrategy) Insert(rule string) {
	r, err := c.payloadToRule(rule)
	if err != nil {
		if c.domainOnly {
			c.err = err
			return
		}
		log.Warnln("parse classical rule [%s] error: %s", rule, err.Error())
	} else {
		c.rules = append(c.rules, r)
		c.count++
	}
}

func (c *classicalStrategy) payloadToRule(rule string) (C.Rule, error) {
	tp, payload, target, params := common.ParseRulePayload(rule, false)
	if c.domainOnly {
		if payload == "" {
			return nil, fmt.Errorf("blacklist rule-set requires a non-empty payload: %s", rule)
		}
		switch tp {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD":
		default:
			return nil, fmt.Errorf("blacklist rule-set only accepts DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX and DOMAIN-WILDCARD: %s", rule)
		}
		if len(params) != 0 {
			return nil, fmt.Errorf("blacklist rule-set does not accept targets or extra parameters: %s", rule)
		}
	}
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type on classical rule-set: %s", tp)
	}
	return c.parse(tp, payload, target, params, nil)
}

func (c *classicalStrategy) FinishInsert() {}

func NewClassicalStrategy(parse common.ParseRuleFunc) *classicalStrategy {
	return &classicalStrategy{rules: []C.Rule{}, parse: parse}
}
