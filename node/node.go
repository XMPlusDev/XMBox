package node

import (
	"fmt"
	"log"
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

type builtRule struct {
	tag  string
	rule adapter.Rule
}

// Manager creates and removes sing-box inbounds, outbounds, and per-subscription
// relay routing rules for node configurations.
type Manager struct {
	coreInstance *instance.Instance
	
	client     api.API
	access     sync.Mutex

	rulesMu    sync.Mutex
	relayRules map[string]adapter.Rule
	blockRules map[string]adapter.Rule

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
		blockRules:     make(map[string]adapter.Rule),
		inboundScopes:  make(map[string][]*adapter.Scope),
		outboundScopes: make(map[string]*adapter.Scope),
		client:         client,
		access:         sync.Mutex{},
	}
}

// AddNode builds a node's inbounds from nodeInfo, registers them with
// sing-box, and starts them in every lifecycle stage. A node is usually one
// inbound, but a ShadowTLS-fronted node is a chain: the protocol on loopback
// plus the ShadowTLS listener that detours into it.
func (m *Manager) AddNode(nodeInfo *api.NodeInfo, tag string, config *Config, pusher func(string, any) error, blockRules []api.BlockRule) error {
	inbounds, err := getInboundOptions(tag, nodeInfo, config, pusher, m.client)
	if err != nil {
		return fmt.Errorf("build inbound config: %w", err)
	}

	// Block rules go in before any inbound starts accepting connections.
	if err := m.SetBlockRules(tag, blockRules); err != nil {
		return fmt.Errorf("set block rules: %w", err)
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
			for _, rollbackKick := range created {
				_ = m.removeInbound(rollbackKick.Tag())
			}
			_ = m.RemoveBlockRules(tag)
			return fmt.Errorf("create inbound %q: %w", inbound.Tag, err)
		}
		inboundObj, _ := b.Inbound().Get(inbound.Tag)
		created = append(created, inboundObj)
	}

	if err := m.startInbounds(created); err != nil {
		for _, rollbackKick := range created {
			_ = m.removeInbound(rollbackKick.Tag())
		}
		_ = m.RemoveBlockRules(tag)
		return fmt.Errorf("start inbound %q: %w", created[len(created)-1].Tag(), err)
	}
	return nil
}

// SetBlockRules replaces the node's block rules in one swap, so there is no
// moment where the old rules are gone and the new ones are not yet in. The
// rules are placed before the relay rules (first match wins, and a relayed
// user's blocked traffic must not be routed to the relay).
func (m *Manager) SetBlockRules(tag string, rules []api.BlockRule) error {
	ctx := m.coreInstance.GetCtx()
	logger := m.coreInstance.GetLogFactory().Logger()

	type built struct {
		tag  string
		rule adapter.Rule
	}
	fresh := make([]built, 0, len(rules))
	closeFresh := func() {
		for _, f := range fresh {
			closeRule(f.rule)
		}
	}

	for i, r := range rules {
		id := r.ID
		if id <= 0 {
			id = i
		}
		opts, err := BlockRuleOptions(tag, r)
		if err != nil {
			closeFresh()
			return fmt.Errorf("block rule %d: %w", r.ID, err)
		}
		rule, err := R.NewRule(ctx, logger, opts, true)
		if err != nil {
			closeFresh()
			return fmt.Errorf("block rule %d: build: %w", r.ID, err)
		}
		if err := rule.Start(); err != nil {
			closeFresh()
			return fmt.Errorf("block rule %d: start: %w", r.ID, err)
		}
		fresh = append(fresh, built{BlockRuleTag(tag, id), rule})
	}

	rulesField, err := routerRulesField(m.coreInstance.GetBox().Router())
	if err != nil {
		closeFresh()
		return err
	}

	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()

	// Drop this node's previous block rules from the map and the router.
	prefix := tag + "_block_"
	old := make(map[adapter.Rule]struct{})
	for t, r := range m.blockRules {
		if strings.HasPrefix(t, prefix) {
			old[r] = struct{}{}
			delete(m.blockRules, t)
		}
	}

	current := rulesField.Interface().([]adapter.Rule)
	kept := make([]adapter.Rule, 0, len(current)+len(fresh))
	for _, r := range current {
		if _, drop := old[r]; !drop {
			kept = append(kept, r)
		}
	}

	at := m.firstRelayIndex(kept)
	updated := make([]adapter.Rule, 0, len(kept)+len(fresh))
	updated = append(updated, kept[:at]...)
	for _, f := range fresh {
		updated = append(updated, f.rule)
		m.blockRules[f.tag] = f.rule
	}
	updated = append(updated, kept[at:]...)
	rulesField.Set(reflect.ValueOf(updated))

	for r := range old {
		closeRule(r)
	}
	return nil
}

// RemoveBlockRules removes all of a node's block rules.
func (m *Manager) RemoveBlockRules(tag string) error {
	return m.SetBlockRules(tag, nil)
}

// firstRelayIndex returns the index of the first relay rule in rules, or
// len(rules) when there is none. Callers must hold rulesMu.
func (m *Manager) firstRelayIndex(rules []adapter.Rule) int {
	for i, r := range rules {
		for _, relay := range m.relayRules {
			if r == relay {
				return i
			}
		}
	}
	return len(rules)
}

func closeRule(r adapter.Rule) {
	if c, ok := r.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// RemoveNode removes every inbound belonging to the node with the given tag.
func (m *Manager) RemoveNode(tag string) error {
	// Front first: stop accepting before the protocol behind it disappears.
	if err := m.removeInbound(api.ShadowTLSTag(tag)); err != nil {
		return err
	}
	if err := m.removeInbound(tag); err != nil {
		return err
	}
	return m.RemoveBlockRules(tag)
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
	lock := access.Addr()
	lock.MethodByName("Lock").Call(nil)
	defer lock.MethodByName("Unlock").Call(nil)

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

// addRelayOutbounds creates the per-subscription relay outbounds under relayTag.
func (m *Manager) addRelayOutbounds(relayNodeInfo *api.RelayNodeInfo, relayTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for i := range *subscriptionInfo {
		subscription := &(*subscriptionInfo)[i]
		passwd := subscription.Passwd
		if C.Contains(shadowaead_2022.List, strings.ToLower(relayNodeInfo.Cipher)) {
			passwd = fmt.Sprintf("%s:%s", relayNodeInfo.ServerKey, subscription.Passwd)
		}

		outbounds, err := OutboundRelayBuilder(relayNodeInfo, relayTag, subscription, passwd)
		if err != nil {
			return fmt.Errorf("failed to build relay outbound for Id %d: %w", subscription.Id, err)
		}
		// Reverse order: the ShadowTLS outbound a protocol detours through has
		// to exist before the protocol that names it.
		for j := len(outbounds) - 1; j >= 0; j-- {
			if err := m.addOutbound(outbounds[j]); err != nil {
				return fmt.Errorf("failed to add relay outbound for Id %d: %w", subscription.Id, err)
			}
		}
	}
	return nil
}

// buildRelayRules builds and starts the relay router rules without installing them.
func (m *Manager) buildRelayRules(mainTag, relayTag string, subscriptionInfo *[]api.SubscriptionInfo) ([]builtRule, error) {
	ctx := m.coreInstance.GetCtx()
	logger := m.coreInstance.GetLogFactory().Logger()

	built := make([]builtRule, 0, len(*subscriptionInfo))
	fail := func(err error) ([]builtRule, error) {
		for _, b := range built {
			closeRule(b.rule)
		}
		return nil, err
	}

	for i := range *subscriptionInfo {
		subscription := &(*subscriptionInfo)[i]
		options, err := RelayRuleOptions(mainTag, relayTag, subscription)
		if err != nil {
			return fail(fmt.Errorf("failed to build relay rule for Id %d: %w", subscription.Id, err))
		}
		rule, err := R.NewRule(ctx, logger, options, true)
		if err != nil {
			return fail(fmt.Errorf("build rule for Id %d: %w", subscription.Id, err))
		}
		if err := rule.Start(); err != nil {
			return fail(fmt.Errorf("start rule for Id %d: %w", subscription.Id, err))
		}
		built = append(built, builtRule{tag: RelayRuleTag(relayTag, subscription), rule: rule})
	}
	return built, nil
}

// AddRelayTag adds a node's relay: outbounds first, then the rules that use them.
func (m *Manager) AddRelayTag(relayNodeInfo *api.RelayNodeInfo, relayTag string, mainTag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	if err := m.addRelayOutbounds(relayNodeInfo, relayTag, subscriptionInfo); err != nil {
		return err
	}
	for i := range *subscriptionInfo {
		subscription := &(*subscriptionInfo)[i]
		ruleOptions, err := RelayRuleOptions(mainTag, relayTag, subscription)
		if err != nil {
			return fmt.Errorf("failed to build relay rule for Id %d: %w", subscription.Id, err)
		}
		if err := m.addRouterRule(RelayRuleTag(relayTag, subscription), ruleOptions); err != nil {
			return fmt.Errorf("failed to add relay rule for Id %d: %w", subscription.Id, err)
		}
	}
	return nil
}

// SwapRelay replaces a node's relay without a moment where relayed users have
// no relay rule. The new outbounds are created under newTag first. Then every
// old relay rule is replaced by the new ones in a single assignment of the
// router's rule list, in the same position, so block rules stay in front of
// them. The old outbounds are removed after the swap.
// oldTag is "" and oldSubs is nil when there is no relay yet.
func (m *Manager) SwapRelay(oldTag string, oldSubs *[]api.SubscriptionInfo, relayNodeInfo *api.RelayNodeInfo, newTag, mainTag string, subs *[]api.SubscriptionInfo) error {
	// 1. New outbounds under the new tag, the old relay keeps serving.
	if err := m.addRelayOutbounds(relayNodeInfo, newTag, subs); err != nil {
		_ = m.RemoveRelayTag(newTag, subs)
		return err
	}

	// 2. Build the new rules before touching the router.
	fresh, err := m.buildRelayRules(mainTag, newTag, subs)
	if err != nil {
		_ = m.RemoveRelayTag(newTag, subs)
		return err
	}

	rulesField, err := routerRulesField(m.coreInstance.GetBox().Router())
	if err != nil {
		for _, f := range fresh {
			closeRule(f.rule)
		}
		_ = m.RemoveRelayTag(newTag, subs)
		return err
	}

	// 3. One swap.
	m.rulesMu.Lock()
	old := make(map[adapter.Rule]string)
	if oldSubs != nil {
		for i := range *oldSubs {
			tag := RelayRuleTag(oldTag, &(*oldSubs)[i])
			if r, ok := m.relayRules[tag]; ok {
				old[r] = tag
			}
		}
	}

	current := rulesField.Interface().([]adapter.Rule)
	updated := make([]adapter.Rule, 0, len(current)+len(fresh))
	inserted := false
	insertFresh := func() {
		for _, f := range fresh {
			updated = append(updated, f.rule)
		}
		inserted = true
	}
	for _, r := range current {
		if _, isOld := old[r]; isOld {
			if !inserted {
				insertFresh() // first old relay rule: the new ones take its place
			}
			continue
		}
		updated = append(updated, r)
	}
	if !inserted {
		insertFresh() // no old relay rules: append behind the existing rules
	}
	rulesField.Set(reflect.ValueOf(updated))

	for _, tag := range old {
		delete(m.relayRules, tag)
	}
	for _, f := range fresh {
		m.relayRules[f.tag] = f.rule
	}
	m.rulesMu.Unlock()

	// 4. The old relay is out of the router, clean it up.
	for r := range old {
		closeRule(r)
	}
	if oldSubs != nil {
		if err := m.RemoveRelayTag(oldTag, oldSubs); err != nil {
			log.Printf("relay %s: removing old outbounds: %v", oldTag, err)
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

	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()

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

	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()

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
