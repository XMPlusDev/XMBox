package node

import (
	"fmt"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/xmplusdev/xmbox/api"
	sub_module "github.com/xmplusdev/xmbox/subscription"
)

// RelayRuleTag returns the per-subscription router rule tag for a relay.
func RelayRuleTag(relayTag string, subscription *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s_%d", relayTag, subscription.Id)
}

// RelayRuleOptions builds a sing-box route rule that sends the given
// subscription's traffic arriving on the main inbound (tag) to the
// per-subscription relay outbound. It mirrors XMRay's RelayRouterBuilder.
func RelayRuleOptions(tag string, relayTag string, subscription *api.SubscriptionInfo) (option.Rule, error) {
	if subscription == nil {
		return option.Rule{}, fmt.Errorf("subscription is nil")
	}

	rule := option.Rule{
		Type: "default",
	}
	rule.DefaultOptions.Inbound = badoption.Listable[string]{tag}
	rule.DefaultOptions.AuthUser = badoption.Listable[string]{sub_module.BuildUserTag(tag, subscription)}
	rule.DefaultOptions.RuleAction.Action = "route"
	rule.DefaultOptions.RuleAction.RouteOptions.Outbound = RelayOutboundTag(relayTag, subscription)

	return rule, nil
}
