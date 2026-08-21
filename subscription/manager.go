package subscription

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/counter"

	"github.com/xmplusdev/xmbox/instance"
	"github.com/xmplusdev/xmbox/limiter"
)

// Manager manages per-node subscription lifecycle (add, remove, monitor).
type Manager struct {
	coreInstance *instance.Instance
	client       api.API
}

// NewManager returns a Manager backed by the given instance and API client.
func NewManager(coreInstance *instance.Instance, client api.API) *Manager {
	return &Manager{coreInstance: coreInstance, client: client}
}

// AddSubscriptions registers all subscriptions with the appropriate protocol handler.
func (m *Manager) AddSubscriptions(subscriptionInfo *[]api.SubscriptionInfo, nodeInfo *api.NodeInfo, tag string) error {
	if subscriptionInfo == nil || len(*subscriptionInfo) == 0 {
		return nil
	}

	ib, found := m.coreInstance.GetInbound(tag)
	if !found {
		return errors.New("inbound not found: " + tag)
	}

	protocol := strings.ToLower(nodeInfo.Protocol)
	if err := m.Add(subscriptionInfo, ib, protocol, nodeInfo.NetworkSettings.Flow, nodeInfo.NetworkSettings.Cipher, tag); err != nil {
		return err
	}
	// A ShadowTLS-fronted node authenticates twice: the wrapper admits the
	// connection, the protocol behind it identifies the subscription.
	if nodeInfo.NetworkSettings.ShadowTLS != nil {
		return m.addShadowTLSUsers(subscriptionInfo, tag)
	}
	return nil
}

// addShadowTLSUsers registers subscriptions with the ShadowTLS listener
// fronting a node, keyed by the same user tag as the protocol behind it.
func (m *Manager) addShadowTLSUsers(subscriptions *[]api.SubscriptionInfo, tag string) error {
	frontTag := api.ShadowTLSTag(tag)
	ib, found := m.coreInstance.GetInbound(frontTag)
	if !found {
		return errors.New("inbound not found: " + frontTag)
	}
	mgr, ok := ib.(ShadowTLSUserManager)
	if !ok {
		return fmt.Errorf("inbound %q does not implement ShadowTLSUserManager", frontTag)
	}
	users := make([]option.ShadowTLSUser, len(*subscriptions))
	for i, u := range *subscriptions {
		users[i] = option.ShadowTLSUser{Name: BuildUserTag(tag, &u), Password: u.UUID}
	}
	return mgr.AddUsers(users)
}

// Add dispatches subscriptions to the correct sing-box user manager based on protocol.
func (m *Manager) Add(subscriptions *[]api.SubscriptionInfo, ib interface{ Tag() string }, protocol, flow, cipher, tag string) error {
	ibTag := ib.Tag()

	switch protocol {
	case "vless":
		mgr, ok := ib.(VLESSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VLESSUserManager", ibTag)
		}
		users := make([]option.VLESSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.VLESSUser{Name: BuildUserTag(tag, &u), UUID: u.UUID, Flow: flow}
		}
		return mgr.AddUsers(users)

	case "vmess":
		mgr, ok := ib.(VMessUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VMessUserManager", ibTag)
		}
		users := make([]option.VMessUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.VMessUser{Name: BuildUserTag(tag, &u), UUID: u.UUID}
		}
		return mgr.AddUsers(users)

	case "trojan":
		mgr, ok := ib.(TrojanUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TrojanUserManager", ibTag)
		}
		users := make([]option.TrojanUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.TrojanUser{Name: BuildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(users)

	case "tuic":
		mgr, ok := ib.(TUICUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TUICUserManager", ibTag)
		}
		users := make([]option.TUICUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.TUICUser{Name: BuildUserTag(tag, &u), UUID: u.UUID, Password: u.UUID}
		}
		return mgr.AddUsers(users)

	case "hysteria2":
		mgr, ok := ib.(Hysteria2UserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement Hysteria2UserManager", ibTag)
		}
		users := make([]option.Hysteria2User, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.Hysteria2User{Name: BuildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(users)

	case "naive":
		mgr, ok := ib.(NaiveUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement NaiveUserManager", ibTag)
		}
		users := make([]auth.User, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = auth.User{Username: BuildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(users)

	case "shadowsocks":
		mgr, ok := ib.(ShadowsocksUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowsocksUserManager", ibTag)
		}
		users := make([]option.ShadowsocksUser, 0, len(*subscriptions))
		for _, u := range *subscriptions {
			users = append(users, option.ShadowsocksUser{Name: BuildUserTag(tag, &u), Password: u.Passwd})
		}
		return mgr.AddUsers(users)

	case "anytls":
		mgr, ok := ib.(AnyTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement AnyTLSUserManager", ibTag)
		}
		users := make([]option.AnyTLSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = option.AnyTLSUser{Name: BuildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(users)

	default:
		return fmt.Errorf("AddSubscriptions: unsupported protocol %q", protocol)
	}
}

// RemoveSubscriptions removes users from the inbound and closes their connections.
func (m *Manager) RemoveSubscriptions(emails []string, tag, protocol string) error {
	if len(emails) == 0 {
		return nil
	}

	ib, found := m.coreInstance.GetInbound(tag)
	if !found {
		return errors.New("inbound not found: " + tag)
	}

	if err := m.Remove(ib, strings.ToLower(protocol), emails); err != nil {
		return err
	}

	// Detected by presence rather than passed in, since callers only have the
	// node's protocol. Leaving a revoked user on the wrapper would still let
	// them complete the ShadowTLS handshake.
	if front, found := m.coreInstance.GetInbound(api.ShadowTLSTag(tag)); found {
		mgr, ok := front.(ShadowTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowTLSUserManager", front.Tag())
		}
		if err := mgr.DelUsers(emails); err != nil {
			return err
		}
	}

	for _, u := range emails {
		m.coreInstance.GetDispatcher().CloseUserConns(tag, u)
	}
	return nil
}

// Remove calls DelUsers on the appropriate sing-box user manager.
func (m *Manager) Remove(ib interface{ Tag() string }, protocol string, emails []string) error {
	switch protocol {
	case "vless":
		mgr, ok := ib.(VLESSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VLESSUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "vmess":
		mgr, ok := ib.(VMessUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VMessUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "trojan":
		mgr, ok := ib.(TrojanUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TrojanUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "tuic":
		mgr, ok := ib.(TUICUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TUICUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "hysteria2":
		mgr, ok := ib.(Hysteria2UserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement Hysteria2UserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "naive":
		mgr, ok := ib.(NaiveUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement NaiveUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "shadowsocks":
		mgr, ok := ib.(ShadowsocksUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowsocksUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	case "anytls":
		mgr, ok := ib.(AnyTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement AnyTLSUserManager", ib.Tag())
		}
		return mgr.DelUsers(emails)
	default:
		return fmt.Errorf("RemoveSubscriptions: unsupported protocol %q", protocol)
	}
}

// reverbBatchSize is how many records go into one Reverb push.
//
// Reverb enforces a per-message ceiling (config/reverb.php max_message_size,
// 10,000 bytes by default) and rejects anything larger on receipt. That
// rejection is invisible to the sender — the local write has already returned
// success — so a batch must be kept under the ceiling rather than discovered
// to be over it. A traffic record is at most ~77 bytes with int64 counters at
// full width, an online-IP record ~78 with an IPv6 address, so 100 records plus
// the envelope stays under 8 KB either way.
const reverbBatchSize = 100

// reportTraffic delivers drained counters to the panel and resets only what was
// actually delivered.
//
// Batches are pushed one at a time and reset individually. Whatever the push
// could not deliver is retried over the HTTP API and reset only if that
// succeeds, so a failure at either layer leaves the counters intact for the
// next cycle instead of silently dropping the traffic.
func (m *Manager) reportTraffic(pending *limiter.PendingTraffic, logPrefix string, pusher func(string, any) error) {
	var undelivered []*limiter.PendingTraffic
	pushed := 0

	for _, chunk := range pending.Chunk(reverbBatchSize) {
		if pusher == nil {
			undelivered = append(undelivered, chunk)
			continue
		}
		traffic := make([]api.Traffic, len(chunk.Result))
		for idx, t := range chunk.Result {
			traffic[idx] = api.Traffic{Id: t.Id, Upload: t.Upload, Download: t.Download}
		}
		if err := pusher("traffic_report", traffic); err != nil {
			log.Printf("%s Failed to push traffic data via Reverb: %v", logPrefix, err)
			undelivered = append(undelivered, chunk)
			continue
		}
		limiter.ResetTraffic(chunk)
		pushed += len(chunk.Result)
	}
	if pushed > 0 {
		log.Printf("%s Pushed %d Traffic Usage Data via Reverb", logPrefix, pushed)
	}
	if len(undelivered) == 0 {
		return
	}

	records := make([]api.SubscriptionTraffic, 0, len(undelivered)*reverbBatchSize)
	for _, chunk := range undelivered {
		records = append(records, chunk.Result...)
	}
	if err := m.client.ReportTraffic(&records); err != nil {
		log.Print(err)
		return
	}
	log.Printf("%s Report %d Subscription Traffic Usage Data", logPrefix, len(records))
	for _, chunk := range undelivered {
		limiter.ResetTraffic(chunk)
	}
}

// SubscriptionMonitor reports traffic and online IPs to the panel. If pusher
// is non-nil, reports are pushed over the Reverb WebSocket instead of the
// regular HTTP API.
func (m *Manager) SubscriptionMonitor(tag, logPrefix string, pusher func(string, any) error) error {
	tc, ok := m.coreInstance.GetDispatcher().GetTrafficCounter(tag)
	if !ok {
		return nil
	}

	if pending := limiter.DrainDeltas(tag, tc); pending != nil {
		m.reportTraffic(pending, logPrefix, pusher)
	}

	onlineIPs, err := limiter.GetOnlineIPs(tag)
	if err != nil {
		log.Print(err)
	} else if onlineIPs != nil && len(*onlineIPs) > 0 {
		pushed := false
		if pusher != nil {
			// Batched for the same reason as traffic, and this list is often
			// the larger of the two: ip_limit allows several records per
			// subscription.
			pushed = true
			for start := 0; start < len(*onlineIPs); start += reverbBatchSize {
				batch := (*onlineIPs)[start:min(start+reverbBatchSize, len(*onlineIPs))]
				aliveIPs := make([]api.AliveIP, len(batch))
				for idx, ip := range batch {
					aliveIPs[idx] = api.AliveIP{Id: ip.Id, IP: ip.IP}
				}
				if err := pusher("online_ips", aliveIPs); err != nil {
					log.Printf("%s Failed to push online IPs via Reverb: %v", logPrefix, err)
					pushed = false
					break
				}
			}
			if pushed {
				log.Printf("%s Pushed %d Online IPs Data via Reverb", logPrefix, len(*onlineIPs))
			}
		}
		if !pushed {
			if err = m.client.ReportOnlineIPs(onlineIPs); err != nil {
				log.Print(err)
			} else {
				log.Printf("%s Report %d Subscription Online IPs Data", logPrefix, len(*onlineIPs))
			}
		}
	}

	return nil
}

// CompareSubscriptions diffs two subscription lists, returning deleted, added, and modified entries.
func CompareSubscriptions(old, new *[]api.SubscriptionInfo) (deleted, added, modified []api.SubscriptionInfo) {
	if old == nil && new == nil {
		return nil, nil, nil
	}
	if old == nil {
		return nil, *new, nil
	}
	if new == nil {
		return *old, nil, nil
	}

	oldMap := make(map[int]api.SubscriptionInfo, len(*old))
	for _, v := range *old {
		oldMap[v.Id] = v
	}
	newMap := make(map[int]api.SubscriptionInfo, len(*new))
	for _, v := range *new {
		newMap[v.Id] = v
	}

	for id, o := range oldMap {
		if _, exists := newMap[id]; !exists {
			deleted = append(deleted, o)
		}
	}
	for id, n := range newMap {
		if o, exists := oldMap[id]; !exists {
			added = append(added, n)
		} else if o.SpeedLimit != n.SpeedLimit || o.IPLimit != n.IPLimit || o.UUID != n.UUID {
			modified = append(modified, n)
		}
	}
	return deleted, added, modified
}

// GetEmails returns the composed email keys for a slice of subscriptions.
func GetEmails(subscriptions []api.SubscriptionInfo, tag string) []string {
	if len(subscriptions) == 0 {
		return nil
	}
	emails := make([]string, len(subscriptions))
	for i, u := range subscriptions {
		emails[i] = fmt.Sprintf("%s_%s", tag, u.Email)
	}
	return emails
}

// GetOnlineIPs delegates to the limiter package.
func (m *Manager) GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	return limiter.GetOnlineIPs(tag)
}

// DrainDeltas delegates to the limiter package.
func (m *Manager) DrainDeltas(tag string, tc *counter.TrafficCounter) *limiter.PendingTraffic {
	return limiter.DrainDeltas(tag, tc)
}

// ResetTraffic delegates to the limiter package.
func (m *Manager) ResetTraffic(pending *limiter.PendingTraffic) {
	limiter.ResetTraffic(pending)
}

// BuildUserTag constructs a composite key from the node tag and user email.
func BuildUserTag(tag string, sub *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s_%s", tag, sub.Email)
}
