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
	inboundprotocol "github.com/xmplusdev/xmbox/inbound/protocol"
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
	return m.Add(subscriptionInfo, ib, protocol, nodeInfo.NetworkSettings.Flow, nodeInfo.NetworkSettings.Cipher, tag)
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

	case "shadowtls":
		mgr, ok := ib.(ShadowTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowTLSUserManager", ibTag)
		}
		// UUID authenticates at the ShadowTLS layer, Passwd keys the inner
		// shadowsocks layer. Passwd is used because the inner cipher needs a
		// base64 key of at least 16 bytes, which a UUID is not.
		users := make([]inboundprotocol.ShadowTLSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			users[i] = inboundprotocol.ShadowTLSUser{
				Name:          BuildUserTag(tag, &u),
				Password:      u.UUID,
				InnerPassword: u.Passwd,
			}
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
	case "shadowtls":
		mgr, ok := ib.(ShadowTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowTLSUserManager", ib.Tag())
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

// SubscriptionMonitor reports traffic and online IPs to the panel. If pusher
// is non-nil, reports are pushed over the Reverb WebSocket instead of the
// regular HTTP API.
func (m *Manager) SubscriptionMonitor(tag, logPrefix string, pusher func(string, any) error) error {
	tc, ok := m.coreInstance.GetDispatcher().GetTrafficCounter(tag)
	if !ok {
		return nil
	}

	pending := limiter.DrainDeltas(tag, tc)
	if pending != nil && len(pending.Result) > 0 {
		pushed := false
		if pusher != nil {
			traffic := make([]api.Traffic, len(pending.Result))
			for idx, t := range pending.Result {
				traffic[idx] = api.Traffic{Id: t.Id, Upload: t.Upload, Download: t.Download}
			}
			if err := pusher("traffic_report", traffic); err != nil {
				log.Printf("%s Failed to push traffic data via Reverb: %v", logPrefix, err)
			} else {
				limiter.ResetTraffic(pending)
				log.Printf("%s Pushed %d Traffic Usage Data via Reverb", logPrefix, len(pending.Result))
				pushed = true
			}
		}
		if !pushed {
			if err := m.client.ReportTraffic(&pending.Result); err != nil {
				log.Print(err)
			} else {
				log.Printf("%s Report %d Subscription Traffic Usage Data", logPrefix, len(pending.Result))
				limiter.ResetTraffic(pending)
			}
		}
	}

	onlineIPs, err := limiter.GetOnlineIPs(tag)
	if err != nil {
		log.Print(err)
	} else if onlineIPs != nil && len(*onlineIPs) > 0 {
		pushed := false
		if pusher != nil {
			aliveIPs := make([]api.AliveIP, len(*onlineIPs))
			for idx, ip := range *onlineIPs {
				aliveIPs[idx] = api.AliveIP{Id: ip.Id, IP: ip.IP}
			}
			if err := pusher("online_ips", aliveIPs); err != nil {
				log.Printf("%s Failed to push online IPs via Reverb: %v", logPrefix, err)
			} else {
				log.Printf("%s Pushed %d Online IPs Data via Reverb", logPrefix, len(*onlineIPs))
				pushed = true
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

