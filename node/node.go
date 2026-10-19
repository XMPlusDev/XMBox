package node

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	sboxInbound "github.com/sagernet/sing-box/adapter/inbound"
	sboxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/core/instance"
)

// Manager creates and removes sing-box inbounds, outbounds, and per-subscription
// relay routing rules for node configurations.
type Manager struct {
	coreInstance *instance.Instance
	
	client     api.API

	relayMu    sync.Mutex
	relayRules map[string]adapter.Rule

	// scopeMu guards inboundScopes and outboundScopes.
	scopeMu sync.Mutex
	// inboundScopes records the per-stage child scopes startInbounds hands to
	// each hot-added inbound, in ListStartStages order, so removeInbound can
	// stop them in reverse order.
	inboundScopes map[string][]*adapter.Scope
	// outboundScopes records the scope addOutbound hands to each hot-added
	// outbound, so removeOutbound can stop it in reverse order.
	outboundScopes map[string]*adapter.Scope
}

// NewManager returns a Manager backed by the given instance.
func NewManager(coreInstance *instance.Instance, client api.API) *Manager {
	return &Manager{
		coreInstance:   coreInstance,
		relayRules:     make(map[string]adapter.Rule),
		inboundScopes:  make(map[string][]*adapter.Scope),
		outboundScopes: make(map[string]*adapter.Scope),
		client:     client,
	}
}

// AddNode builds a node's inbounds from nodeInfo, registers them with
// sing-box, and starts them in every lifecycle stage. A node is usually one
// inbound, but a ShadowTLS-fronted node is a chain: the protocol on loopback
// plus the ShadowTLS listener that detours into it.
func (m *Manager) AddNode(nodeInfo *api.NodeInfo, tag string, config *Config, pusher func(string, any) error) error {
	inbounds, err := getInboundOptions(tag, nodeInfo, config, pusher, m.client)
	if err != nil {
		return fmt.Errorf("build inbound config: %w", err)
	}

	b := m.coreInstance.GetBox()
	created := make([]adapter.Inbound, 0, len(inbounds))
	for _, inbound := range inbounds {
		if err := b.Inbound().Create(
			m.coreInstance.GetCtx(),
			b.Router(),
			m.coreInstance.GetLogFactory().NewLogger(
				F.ToString("inbound/", inbound.Type, "[", inbound.Tag, "]"),
			),
			inbound.Tag,
			inbound.Type,
			inbound.Options,
		); err != nil {
			// Roll back whatever is already up, so a half-built node never
			// lingers — a ShadowTLS listener without its protocol behind it
			// would accept connections and drop every one.
			for _, rollbackKick := range created {
				_ = m.removeInbound(rollbackKick.Tag())
			}
			return fmt.Errorf("create inbound %q: %w", inbound.Tag, err)
		}
		inboundObj, _ := b.Inbound().Get(inbound.Tag)
		created = append(created, inboundObj)
	}

	if err := m.startInbounds(created); err != nil {
		for _, rollbackKick := range created {
			_ = m.removeInbound(rollbackKick.Tag())
		}
		return fmt.Errorf("start inbound %q: %w", created[len(created)-1].Tag(), err)
	}
	return nil
}

// RemoveNode removes every inbound belonging to the node with the given tag.
func (m *Manager) RemoveNode(tag string) error {
	// Front first: stop accepting before the protocol behind it disappears.
	if err := m.removeInbound(api.ShadowTLSTag(tag)); err != nil {
		return err
	}
	return m.removeInbound(tag)
}

// removeInbound removes one inbound by tag, if present.
//
// sing-box removed Manager.Remove from the public managers, so this replays
// the removed logic from adapter/inbound/manager.go on the concrete manager
// type: stop the inbound's scope, then detach it from the manager.
func (m *Manager) removeInbound(tag string) error {
	b := m.coreInstance.GetBox()
	inbound, found := b.Inbound().Get(tag)
	if !found {
		return nil
	}

	m.scopeMu.Lock()
	scopes, ok := m.inboundScopes[tag]
	delete(m.inboundScopes, tag)
	m.scopeMu.Unlock()

	if ok {
		if err := stopInboundScopes(scopes); err != nil {
			return fmt.Errorf("stop inbound %q: %w", tag, err)
		}
	}

	// Endpoints live behind the endpoint manager, whose own registration owns
	// them; only manager-held inbounds can be detached here.
	mgr := b.Inbound()
	concrete, ok := mgr.(*sboxInbound.Manager)
	if !ok {
		return fmt.Errorf("remove inbound %q: %T is not the sing-box inbound manager", tag, mgr)
	}
	if !managerOwned(mgr.Inbounds(), inbound) {
		return nil
	}
	if err := managerSplice(concrete, "inbounds", "inboundByTag", tag, func(item any) bool {
		return item != any(inbound)
	}, nil); err != nil {
		return fmt.Errorf("remove inbound %q: %w", tag, err)
	}
	return nil
}

// startInbounds runs the lifecycle stages of every hot-added inbound, each on
// a fresh child scope every stage, recording the scopes in ListStartStages
// order.
//
// The old manager's Create used to start components itself; the pinned
// sing-box only registers them, so AddNode must run the stages. A stage
// failure stops the scopes already started, leaving the inbound inert but
// still registered for removeInbound to sweep.
func (m *Manager) startInbounds(created []adapter.Inbound) error {
	ctx := m.coreInstance.GetCtx()
	logger := m.coreInstance.GetLogFactory().NewLogger("inbound/hot-add")
	for _, inbound := range created {
		lifecycle, ok := inbound.(adapter.Lifecycle)
		if !ok {
			continue
		}
		scopes := make([]*adapter.Scope, 0, len(adapter.ListStartStages))
		var stageErr error
		for _, stage := range adapter.ListStartStages {
			childScope := adapter.NewScope(ctx, logger)
			if stageErr = childScope.Start(
				F.ToString("inbound/", inbound.Type(), "[", inbound.Tag(), "]"),
				lifecycle,
				stage,
			); stageErr != nil {
				_ = childScope.Close()
				break
			}
			scopes = append(scopes, childScope)
		}
		m.scopeMu.Lock()
		m.inboundScopes[inbound.Tag()] = scopes
		m.scopeMu.Unlock()
		if stageErr != nil {
			_ = stopInboundScopes(scopes)
			return stageErr
		}
	}
	return nil
}

// stopInboundScopes stops the per-stage scopes of one hot-added inbound in
// reverse stage order, so a listener opened at Start closes before the
// service kept alive at Initialize.
func stopInboundScopes(scopes []*adapter.Scope) error {
	var firstErr error
	for i := len(scopes) - 1; i >= 0; i-- {
		if err := scopes[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

	outbound, found := b.Outbound().Outbound(out.Tag)
	if !found {
		_ = m.removeOutbound(out.Tag)
		return fmt.Errorf("create outbound %q: manager lookup failed", out.Tag)
	}

	// Outbounds hot-added after sing-box started were never started, so run
	// their Start stage now.
	childScope := adapter.NewScope(
		m.coreInstance.GetCtx(),
		m.coreInstance.GetLogFactory().NewLogger(
			F.ToString("outbound/", out.Type, "[", out.Tag, "]"),
		),
	)
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if isLifecycle {
		for _, stage := range adapter.ListStartStages {
			if err := childScope.Start(
				F.ToString("outbound/", out.Type, "[", out.Tag, "]"),
				lifecycle,
				stage,
			); err != nil {
				_ = childScope.Close()
				_ = m.removeOutbound(out.Tag)
				return fmt.Errorf("start outbound %q stage %s: %w", out.Tag, stage, err)
			}
		}
	}
	m.scopeMu.Lock()
	m.outboundScopes[out.Tag] = childScope
	m.scopeMu.Unlock()
	return nil
}

// removeOutbound removes the outbound with the given tag, if present.
//
// The pinned sing-box no longer exposes a Remove method on the outbound
// manager either, so this replays the same detach-and-stop as removeInbound:
// delete the outbound's manager registrations and children first, then close
// its scope in reverse stage order.
func (m *Manager) removeOutbound(tag string) error {
	b := m.coreInstance.GetBox()
	outbound, found := b.Outbound().Outbound(tag)
	if !found {
		return nil
	}

	m.scopeMu.Lock()
	scopes, ok := m.outboundScopes[tag]
	delete(m.outboundScopes, tag)
	m.scopeMu.Unlock()

	if ok {
		if err := scopes.Close(); err != nil {
			return fmt.Errorf("stop outbound %q: %w", tag, err)
		}
	}

	// Same endpoint-manager guard as the inbound side.
	mgr := b.Outbound()
	concrete, ok := mgr.(*sboxOutbound.Manager)
	if !ok {
		return fmt.Errorf("remove outbound %q: %T is not the sing-box outbound manager", tag, mgr)
	}
	if !managerOwned(mgr.Outbounds(), outbound) {
		return nil
	}
	if err := managerSplice(concrete, "outbounds", "outboundByTag", tag, func(item any) bool {
		return item != any(outbound)
	}, func(holder reflect.Value) {
		// Repair the manager default if it pointed at the removed entry,
		// mirroring the old Remove: prefer nothing rather than a
		// dangling outbound.
		def := reflect.NewAt(
			holder.FieldByName("defaultOutbound").Type(),
			unsafe.Pointer(holder.FieldByName("defaultOutbound").UnsafeAddr()),
		).Elem()
		if existing, isOutbound := def.Interface().(adapter.Outbound); isOutbound && existing == outbound {
			def.Set(reflect.Zero(def.Type()))
		}
	}); err != nil {
		return fmt.Errorf("remove outbound %q: %w", tag, err)
	}
	return nil
}

// managerSplice replays the removed sing-box Manager.Remove logic against
// the unexported slice+map fields of the concrete manager, using the same
// unsafe accessor trick as routerRulesField below. It locks the manager's
// access mutex, deletes tag's entry from the map, filters the slice down to
// the entries for which keep returns true, then runs fixup (e.g. repairing
// the outbound manager's default) while still holding the lock.
func managerSplice(holder any, sliceName, mapName, tag string, keep func(item any) bool, fixup func(holder reflect.Value)) error {
	v := reflect.ValueOf(holder)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("unexpected manager type: %s", v.Type())
	}
	settable := func(name string) (reflect.Value, error) {
		f := v.FieldByName(name)
		if !f.IsValid() {
			return reflect.Value{}, fmt.Errorf("manager has no %s field", name)
		}
		return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem(), nil
	}
	access, err := settable("access")
	if err != nil {
		return err
	}
	access.MethodByName("Lock").Call(nil)
	defer access.MethodByName("Unlock").Call(nil)

	byTag, err := settable(mapName)
	if err != nil {
		return err
	}
	byTag.SetMapIndex(reflect.ValueOf(tag), reflect.Value{})
	current, err := settable(sliceName)
	if err != nil {
		return err
	}
	kept := reflect.MakeSlice(current.Type(), 0, current.Len())
	for i := range current.Len() {
		if keep(current.Index(i).Interface()) {
			kept = reflect.Append(kept, current.Index(i))
		}
	}
	current.Set(kept)
	if fixup != nil {
		fixup(v)
	}
	return nil
}

// managerOwned checks whether item is one of the manager-owned entries rather
// than an endpoint the managers fall through to.
func managerOwned(list, item any) bool {
	items := reflect.ValueOf(list)
	want := reflect.ValueOf(item)
	for i := range items.Len() {
		if items.Index(i).Interface() == want.Interface() {
			return true
		}
	}
	return false
}
// matching routing rule for each subscription, sending that user's traffic
// arriving on mainTag's inbound to relayNodeInfo.
func (m *Manager) AddRelayTag(relayNodeInfo *api.RelayNodeInfo, relayTag string, mainTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		passwd := subscription.Passwd
		if C.Contains(shadowaead_2022.List, strings.ToLower(relayNodeInfo.Cipher)) {
			passwd = fmt.Sprintf("%s:%s", relayNodeInfo.ServerKey, subscription.Passwd)
		}

		outbounds, err := OutboundRelayBuilder(relayNodeInfo, relayTag, &subscription, passwd)
		if err != nil {
			return fmt.Errorf("failed to build relay outbound for Id %d: %w", subscription.Id, err)
		}
		// Reverse order: the ShadowTLS outbound a protocol detours through has
		// to exist before the protocol that names it.
		for i := len(outbounds) - 1; i >= 0; i-- {
			if err := m.addOutbound(outbounds[i]); err != nil {
				return fmt.Errorf("failed to add relay outbound for Id %d: %w", subscription.Id, err)
			}
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
		outboundTag := RelayOutboundTag(relayTag, &subscription)
		// Protocol first, then the ShadowTLS outbound it detours through, so
		// nothing is left naming an outbound that has already gone.
		if err := m.removeOutbound(outboundTag); err != nil {
			return fmt.Errorf("failed to remove relay outbound for Id %d: %w", subscription.Id, err)
		}
		if err := m.removeOutbound(api.ShadowTLSTag(outboundTag)); err != nil {
			return fmt.Errorf("failed to remove relay shadowtls outbound for Id %d: %w", subscription.Id, err)
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
