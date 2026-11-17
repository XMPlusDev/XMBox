package node

import (
	"fmt"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
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

// BlockRuleTag returns the router rule tag for one panel block rule.
func BlockRuleTag(tag string, id int) string {
	return fmt.Sprintf("%s_block_%d", tag, id)
}

// BlockRuleOptions builds a sing-box route rule that rejects the traffic a
// panel block rule matches on this node's inbound. The panel's own inbound
// condition is ignored on purpose: a tag typed there could block another
// node running in the same process.
func BlockRuleOptions(tag string, r api.BlockRule) (option.Rule, error) {
	rule := option.Rule{Type: "default"}
	d := &rule.DefaultOptions

	d.Inbound = badoption.Listable[string]{tag}
	if len(r.Network) > 0 {
		d.Network = badoption.Listable[string](r.Network)
	}
	if len(r.Protocol) > 0 {
		d.Protocol = badoption.Listable[string](r.Protocol)
	}
	if len(r.Domain) > 0 {
		d.Domain = badoption.Listable[string](r.Domain)
	}
	if len(r.DomainSuffix) > 0 {
		d.DomainSuffix = badoption.Listable[string](r.DomainSuffix)
	}
	if len(r.DomainKeyword) > 0 {
		d.DomainKeyword = badoption.Listable[string](r.DomainKeyword)
	}
	if len(r.DomainRegex) > 0 {
		d.DomainRegex = badoption.Listable[string](r.DomainRegex)
	}
	if len(r.SourceIPCIDR) > 0 {
		list, err := toPrefixables(r.SourceIPCIDR)
		if err != nil {
			return option.Rule{}, err
		}
		d.SourceIPCIDR = list
	}
	if len(r.IPCIDR) > 0 {
		list, err := toPrefixables(r.IPCIDR)
		if err != nil {
			return option.Rule{}, err
		}
		d.IPCIDR = list
	}
	if len(r.Port) > 0 {
		d.Port = badoption.Listable[uint16](r.Port)
	}
	if len(r.PortRange) > 0 {
		d.PortRange = badoption.Listable[string](r.PortRange)
	}

	d.RuleAction.Action = "reject"
	d.RuleAction.RejectOptions.Method = r.Method
	d.RuleAction.RejectOptions.NoDrop = r.NoDrop
	return rule, nil
}

// toPrefixables turns "10.0.0.0/8" or "1.2.3.4" into sing-box prefix options,
// using Prefixable's own JSON parsing.
func toPrefixables(values []string) (badoption.Listable[*badoption.Prefixable], error) {
	out := make(badoption.Listable[*badoption.Prefixable], 0, len(values))
	for _, v := range values {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		p := new(badoption.Prefixable)
		if err := json.Unmarshal(raw, p); err != nil {
			return nil, fmt.Errorf("invalid ip/cidr %q: %w", v, err)
		}
		out = append(out, p)
	}
	return out, nil
}