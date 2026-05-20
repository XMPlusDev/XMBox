package subscription

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/helper/counter"
	"github.com/xmplusdev/xmbox/core/instance"
	"github.com/xmplusdev/xmbox/helper/limiter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	
)

type Manager struct {
	coreInstance *instance.Instance
	client       api.API
}

func NewManager(coreInstance *instance.Instance, client api.API) *Manager {
	return &Manager{coreInstance: coreInstance, client: client}
}

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

func (m *Manager) Add(subscriptions *[]api.SubscriptionInfo, ib interface{ Tag() string }, protocol string, flow string, cipher string, tag string) error {
	ibTag := ib.Tag()

	switch protocol {
	case "vless":
		mgr, ok := ib.(VLESSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VLESSUserManager", ibTag)
		}
		out := make([]option.VLESSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.VLESSUser{Name: buildUserTag(tag, &u), UUID: u.UUID, Flow: flow}
		}
		return mgr.AddUsers(out)

	case "vmess":
		mgr, ok := ib.(VMessUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement VMessUserManager", ibTag)
		}
		out := make([]option.VMessUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.VMessUser{Name: buildUserTag(tag, &u), UUID: u.UUID}
		}
		return mgr.AddUsers(out)

	case "trojan":
		mgr, ok := ib.(TrojanUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TrojanUserManager", ibTag)
		}
		out := make([]option.TrojanUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.TrojanUser{Name: buildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(out)

	case "tuic":
		mgr, ok := ib.(TUICUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement TUICUserManager", ibTag)
		}
		out := make([]option.TUICUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.TUICUser{Name: buildUserTag(tag, &u), UUID: u.UUID, Password: u.UUID}
		}
		return mgr.AddUsers(out)

	case "hysteria2":
		mgr, ok := ib.(Hysteria2UserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement Hysteria2UserManager", ibTag)
		}
		out := make([]option.Hysteria2User, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.Hysteria2User{Name: buildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(out)

	case "naive":
		mgr, ok := ib.(NaiveUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement NaiveUserManager", ibTag)
		}
		out := make([]auth.User, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = auth.User{Username: buildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(out)

	case "shadowsocks":
		mgr, ok := ib.(ShadowsocksUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowsocksUserManager", ibTag)
		}
		out := make([]option.ShadowsocksUser, len(*subscriptions))
		for i, u := range *subscriptions {
			userPass, err := ssPassword(u.UUID, cipher)
			if err != nil {
				fmt.Errorf("Shadowsocks password for [SID: %d] %s error: ", u.Id, err)
				continue
			}
			out[i] = option.ShadowsocksUser{Name: buildUserTag(tag, &u), Password: userPass }
		}
		return mgr.AddUsers(out)

	case "shadowtls":
		mgr, ok := ib.(ShadowTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement ShadowTLSUserManager", ibTag)
		}
		out := make([]option.ShadowTLSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.ShadowTLSUser{Name: buildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(out)

	case "anytls":
		mgr, ok := ib.(AnyTLSUserManager)
		if !ok {
			return fmt.Errorf("inbound %q does not implement AnyTLSUserManager", ibTag)
		}
		out := make([]option.AnyTLSUser, len(*subscriptions))
		for i, u := range *subscriptions {
			out[i] = option.AnyTLSUser{Name: buildUserTag(tag, &u), Password: u.UUID}
		}
		return mgr.AddUsers(out)

	default:
		return fmt.Errorf("AddSubscriptions: unsupported protocol %q", protocol)
	}
}

func buildUserTag(tag string, subscription *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s_%s", tag, subscription.Email)
}

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

func ssPassword(password string, method string) (string, error) {
	var userKey string
	if len(password) < 16 {
		return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 16")
	}
	
	switch strings.ToLower(method) {
		case "2022-blake3-aes-128-gcm":
			userKey = password[:16]
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			if len(password) < 32 {
				return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 32")
			}
			userKey = password[:32]
		default:
			return password, nil	
	}
	
	return base64.StdEncoding.EncodeToString([]byte(userKey)), nil
}

func (m *Manager) RemoveSubscriptions(emails []string, tag string, protocol string) error {
	if len(emails) == 0 {
		return nil
	}

	ib, found := m.coreInstance.GetInbound(tag)
	if !found {
		return errors.New("inbound not found: " + tag)
	}

	protocol = strings.ToLower(protocol)

	if err := m.Remove(ib, protocol, emails); err != nil {
		return err
	}

	for _, u := range emails {
		m.coreInstance.GetDispatcher().CloseUserConns(tag, u)
	}
	return nil
}

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

	oldMap := make(map[int]api.SubscriptionInfo)
	newMap := make(map[int]api.SubscriptionInfo)

	for _, v := range *old {
		oldMap[v.Id] = v
	}
	for _, v := range *new {
		newMap[v.Id] = v
	}

	for id, oldSub := range oldMap {
		if _, exists := newMap[id]; !exists {
			deleted = append(deleted, oldSub)
		}
	}

	for id, newSub := range newMap {
		if oldSub, exists := oldMap[id]; !exists {
			added = append(added, newSub)
		} else if oldSub.SpeedLimit != newSub.SpeedLimit ||
			oldSub.IPLimit != newSub.IPLimit ||
			oldSub.UUID != newSub.UUID ||
			oldSub.TrafficLimit != newSub.TrafficLimit {
			modified = append(modified, newSub)
		}
	}

	return deleted, added, modified
}

func (m *Manager) SubscriptionMonitor(
    tag string,
    logPrefix string,
) error {
    tc, ok := m.coreInstance.GetDispatcher().GetTrafficCounter(tag)
    if !ok {
        return nil
    }
	subscriptionTraffic := m.DrainDeltas(tag, tc)
 
    if len(subscriptionTraffic.Result) > 0 {
        if err := m.client.ReportTraffic(&subscriptionTraffic.Result); err != nil {
            log.Print(err)
        } else {
            log.Printf("%s Report %d Subscription Traffic Usage Data", logPrefix, len(subscriptionTraffic.Result))
			m.ResetTraffic(subscriptionTraffic)
        }
    }
 
    onlineIPs, err := m.GetOnlineIPs(tag)
    if err != nil {
        log.Print(err)
    } else if len(*onlineIPs) > 0 {
        if err = m.client.ReportOnlineIPs(onlineIPs); err != nil {
            log.Print(err)
        } else {
            log.Printf("%s Report %d Subscription Online IPs Data", logPrefix, len(*onlineIPs))
        }
    }
 
    return nil
}

func (m *Manager) GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	return limiter.GetOnlineIPs(tag)
}

func (m *Manager) DrainDeltas(tag string, tc *counter.TrafficCounter) *limiter.PendingTraffic {
	return limiter.DrainDeltas(tag, tc)
}

func (m *Manager) ResetTraffic(pending *limiter.PendingTraffic) {
	limiter.ResetTraffic(pending)
}