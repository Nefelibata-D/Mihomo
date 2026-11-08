package outboundgroup

import (
	weightedsticky "github.com/metacubex/mihomo/adapter/outboundgroup/weighted_sticky_util"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Adapt server scheduling to the existing group and provider lifecycle.
func newWeightedStickyStrategy(name string, config *weightedsticky.Options, testURL string, providers []P.ProxyProvider, candidates func() []C.Proxy) (*weightedsticky.Strategy, error) {
	return weightedsticky.NewStrategy(weightedsticky.StrategyOptions{Name: name, Config: config, TestURL: testURL, Providers: providers, Candidates: candidates})
}

func staticCandidateNames(providers []P.ProxyProvider) ([]string, bool, error) {
	return weightedsticky.StaticCandidateNames(providers)
}
