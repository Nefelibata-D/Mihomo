package outboundgroup

import (
	weightedsticky "github.com/metacubex/mihomo/adapter/outboundgroup/weighted_sticky_util"
	P "github.com/metacubex/mihomo/constant/provider"
)

// weighted_sticky.go is the only weighted-sticky file in this package. It
// adapts the implementation in weighted_sticky_util to LoadBalance's existing
// strategyFn, keeping the upstream-facing surface to one constructor, one
// start hook, one close hook and one candidate pre-check.
func newWeightedStickyStrategy(name string, config *weightedsticky.Options, testURL string) (strategyFn, func(), func(), error) {
	strategy, err := weightedsticky.NewStrategy(weightedsticky.StrategyOptions{
		Name:    name,
		Config:  config,
		TestURL: testURL,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return strategy.SelectProxy, strategy.Start, strategy.Close, nil
}

func staticCandidateNames(providers []P.ProxyProvider) ([]string, bool, error) {
	return weightedsticky.StaticCandidateNames(providers)
}
