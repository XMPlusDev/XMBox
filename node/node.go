package node

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	C "github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/instance"
)

// Manager creates and removes sing-box inbounds, outbounds, and per-subscription
// relay routing rules for node configurations.
type Manager struct {
	coreInstance *instance.Instance

	relayMu    sync.Mutex
	relayRules map[string]adapter.Rule
}

// NewManager returns a Manager backed by the given instance.
func NewManager(coreInstance *instance.Instance) *Manager {
	return &Manager{coreInstance: coreInstance, relayRules: make(map[string]adapter.Rule)}
}

// AddNode builds an inbound from nodeInfo and registers it with sing-box.
func (m *Manager) AddNode(nodeInfo *api.NodeInfo, tag string, config *Config) error {
	inbound, err := getInboundOptions(tag, nodeInfo, config)
	if err != nil {
		return fmt.Errorf("build inbound config: %w", err)
	}

	b := m.coreInstance.GetBox()
	if err := b.Inbound().Create(
		m.coreInstance.GetCtx(),
		b.Router(),
		m.coreInstance.GetLogFactory().NewLogger(
			F.ToString("inbound/", inbound.Type, "[", tag, "]"),
		),
		tag,
		inbound.Type,
		inbound.Options,
	); err != nil {
		return fmt.Errorf("create inbound %q: %w", tag, err)
	}
	return nil
}

// RemoveNode removes the inbound with the given tag from sing-box.
func (m *Manager) RemoveNode(tag string) error {
	b := m.coreInstance.GetBox()
	if _, found := b.Inbound().Get(tag); found {
		if err := b.Inbound().Remove(tag); err != nil {
			return fmt.Errorf("remove inbound %q: %w", tag, err)
		}
	}
	return nil
}

// addOutbound registers a sing-box outbound with the engine.
func (m *Manager) addOutbound(out *option.Outbound) error {
	b := m.coreInstance.GetBox()
	if err := b.Outbound().Create(
		m.coreInstance.GetCtx(),
		b.Router(),
		m.coreInstance.GetLogFactory().NewLogger(
			F.ToString("outbound/", out.Type, "[", out.Tag, "]"),
		),
		out.Tag,
		out.Type,
		out.Options,
	); err != nil {
		return fmt.Errorf("create outbound %q: %w", out.Tag, err)
	}
	return nil
}

// removeOutbound removes the outbound with the given tag, if present.
func (m *Manager) removeOutbound(tag string) error {
	b := m.coreInstance.GetBox()
	if _, found := b.Outbound().Outbound(tag); found {
		if err := b.Outbound().Remove(tag); err != nil {
			return fmt.Errorf("remove outbound %q: %w", tag, err)
		}
	}
	return nil
}

// AddRelayTag builds and registers a per-subscription relay outbound plus a
// matching routing rule for each subscription, sending that user's traffic
// arriving on mainTag's inbound to relayNodeInfo. 
func (m *Manager) AddRelayTag(relayNodeInfo *api.RelayNodeInfo, relayTag string, mainTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		passwd := subscription.Passwd
		if C.Contains(shadowaead_2022.List, strings.ToLower(relayNodeInfo.Cipher)) {
			passwd = fmt.Sprintf("%s:%s", relayNodeInfo.ServerKey, subscription.Passwd)
		}

		out, err := OutboundRelayBuilder(relayNodeInfo, relayTag, &subscription, passwd)
		if err != nil {
			return fmt.Errorf("failed to build relay outbound for Id %d: %w", subscription.Id, err)
		}
		if err := m.addOutbound(out); err != nil {
			return fmt.Errorf("failed to add relay outbound for Id %d: %w", subscription.Id, err)
		}

		ruleOptions, err := RelayRuleOptions(mainTag, relayTag, &subscription)
		if err != nil {
			return fmt.Errorf("failed to build relay rule for Id %d: %w", subscription.Id, err)
		}
		if err := m.addRouterRule(RelayRuleTag(relayTag, &subscription), ruleOptions); err != nil {
			return fmt.Errorf("failed to add relay rule for Id %d: %w", subscription.Id, err)
		}
	}
	return nil
}

// RemoveRelayTag removes the per-subscription relay outbounds previously
// created by AddRelayTag.
func (m *Manager) RemoveRelayTag(relayTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		if err := m.removeOutbound(RelayOutboundTag(relayTag, &subscription)); err != nil {
			return fmt.Errorf("failed to remove relay outbound for Id %d: %w", subscription.Id, err)
		}
	}
	return nil
}

// RemoveRelayRules removes the per-subscription relay routing rules
// previously created by AddRelayTag.
func (m *Manager) RemoveRelayRules(relayTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		if err := m.removeRouterRule(RelayRuleTag(relayTag, &subscription)); err != nil {
			return fmt.Errorf("failed to remove relay rule for Id %d: %w", subscription.Id, err)
		}
	}
	return nil
}

// addRouterRule parses the given option.Rule and appends it to the running
// router's rule set, keyed by ruleTag for later removal. sing-box's
// adapter.Router does not expose a public AddRule API , so
// this reaches into the *route.Router's private rules slice via reflection.
func (m *Manager) addRouterRule(ruleTag string, options option.Rule) error {
	b := m.coreInstance.GetBox()
	rule, err := R.NewRule(m.coreInstance.GetCtx(), m.coreInstance.GetLogFactory().Logger(), options, true)
	if err != nil {
		return fmt.Errorf("build rule: %w", err)
	}
	if err := rule.Start(); err != nil {
		return fmt.Errorf("start rule: %w", err)
	}

	rulesField, err := routerRulesField(b.Router())
	if err != nil {
		return err
	}

	m.relayMu.Lock()
	defer m.relayMu.Unlock()

	current := rulesField.Interface().([]adapter.Rule)
	updated := make([]adapter.Rule, len(current), len(current)+1)
	copy(updated, current)
	updated = append(updated, rule)
	rulesField.Set(reflect.ValueOf(updated))

	m.relayRules[ruleTag] = rule
	return nil
}

// removeRouterRule removes a previously added rule by its tag.
func (m *Manager) removeRouterRule(ruleTag string) error {
	b := m.coreInstance.GetBox()

	m.relayMu.Lock()
	defer m.relayMu.Unlock()

	rule, ok := m.relayRules[ruleTag]
	if !ok {
		return nil
	}

	rulesField, err := routerRulesField(b.Router())
	if err != nil {
		return err
	}

	current := rulesField.Interface().([]adapter.Rule)
	updated := make([]adapter.Rule, 0, len(current))
	for _, r := range current {
		if r != rule {
			updated = append(updated, r)
		}
	}
	rulesField.Set(reflect.ValueOf(updated))

	if closer, ok := rule.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	delete(m.relayRules, ruleTag)
	return nil
}

// routerRulesField returns a settable reflect.Value for the unexported
// `rules []adapter.Rule` field of the *route.Router behind router.
func routerRulesField(router adapter.Router) (reflect.Value, error) {
	v := reflect.ValueOf(router)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("unexpected router type: %s", v.Type())
	}
	f := v.FieldByName("rules")
	if !f.IsValid() {
		return reflect.Value{}, fmt.Errorf("router has no rules field")
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem(), nil
}
