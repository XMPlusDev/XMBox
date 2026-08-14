package node

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/xmplusdev/xmbox/api"
)

// RelayOutboundTag returns the per-subscription outbound tag for a relay.
func RelayOutboundTag(relayTag string, subscription *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s_%d", relayTag, subscription.Id)
}

// OutboundRelayBuilder builds a sing-box outbound that relays a single
// subscription's traffic to a downstream node (relayNodeInfo). It mirrors
func OutboundRelayBuilder(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, passwd string) (*option.Outbound, error) {
	if relayNodeInfo == nil {
		return nil, fmt.Errorf("relayNodeInfo is nil")
	}
	if subscription == nil {
		return nil, fmt.Errorf("subscription is nil")
	}

	server := option.ServerOptions{
		Server:     relayNodeInfo.Address,
		ServerPort: relayNodeInfo.Port,
	}

	transport, err := buildRelayTransport(relayNodeInfo)
	if err != nil {
		return nil, err
	}
	tlsContainer, err := buildRelayTLS(relayNodeInfo)
	if err != nil {
		return nil, err
	}

	out := &option.Outbound{Tag: RelayOutboundTag(tag, subscription)}

	switch strings.ToLower(relayNodeInfo.NodeType) {
	case "vless":
		out.Type = "vless"
		out.Options = &option.VLESSOutboundOptions{
			ServerOptions:                server,
			UUID:                          subscription.UUID,
			Flow:                          relayNodeInfo.Flow,
			Transport:                     transport,
			OutboundTLSOptionsContainer:   tlsContainer,
		}

	case "vmess":
		out.Type = "vmess"
		out.Options = &option.VMessOutboundOptions{
			ServerOptions:               server,
			UUID:                        subscription.UUID,
			Security:                    "auto",
			AlterId:                     0,
			Transport:                   transport,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "trojan":
		out.Type = "trojan"
		out.Options = &option.TrojanOutboundOptions{
			ServerOptions:               server,
			Password:                    subscription.UUID,
			Transport:                   transport,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "shadowsocks":
		out.Type = "shadowsocks"
		out.Options = &option.ShadowsocksOutboundOptions{
			ServerOptions: server,
			Method:        relayNodeInfo.Cipher,
			Password:      passwd,
		}

	case "hysteria2":
		var obfs *option.Hysteria2Obfs
		var realm *option.Hysteria2Realm
		if ns := relayNodeInfo.NetworkSettings; ns != nil {
			if ns.ObfsType != "" {
				obfs = &option.Hysteria2Obfs{
					Type:     ns.ObfsType,
					Password: ns.ObfsPasswd,
				}
				if ns.ObfsType == "gecko" {
					obfs.GeckoOptions = option.Hysteria2ObfsGecko{
						MinPacketSize: ns.GeckoMinPacketSize,
						MaxPacketSize: ns.GeckoMaxPacketSize,
					}
				}
			}
			if ns.RealmServerURL != "" {
				realm = &option.Hysteria2Realm{
					ServerURL: ns.RealmServerURL,
					Token:     ns.RealmToken,
					RealmID:   ns.RealmID,
				}
				if len(ns.RealmSTUNServers) > 0 {
					realm.STUNServers = badoption.Listable[string](ns.RealmSTUNServers)
				}
			}
		}
		out.Type = "hysteria2"
		out.Options = &option.Hysteria2OutboundOptions{
			ServerOptions:               server,
			Password:                    subscription.UUID,
			Obfs:                        obfs,
			Realm:                       realm,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "tuic":
		cc := "bbr"
		if relayNodeInfo.NetworkSettings != nil && relayNodeInfo.NetworkSettings.CongestionControl != "" {
			cc = relayNodeInfo.NetworkSettings.CongestionControl
		}
		out.Type = "tuic"
		out.Options = &option.TUICOutboundOptions{
			ServerOptions:               server,
			UUID:                        subscription.UUID,
			Password:                    subscription.UUID,
			CongestionControl:           cc,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "anytls":
		out.Type = "anytls"
		out.Options = &option.AnyTLSOutboundOptions{
			ServerOptions:               server,
			Password:                    subscription.UUID,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "shadowtls":
		out.Type = "shadowtls"
		out.Options = &option.ShadowTLSOutboundOptions{
			ServerOptions:               server,
			Version:                     3,
			Password:                    subscription.UUID,
			OutboundTLSOptionsContainer: tlsContainer,
		}

	case "naive":
		out.Type = "naive"
		out.Options = &option.NaiveOutboundOptions{
			ServerOptions: server,
			Username:      subscription.Email,
			Password:      subscription.UUID,
		}

	default:
		return nil, fmt.Errorf("unsupported relay node type: %s", relayNodeInfo.NodeType)
	}

	return out, nil
}

func buildRelayTransport(relayNodeInfo *api.RelayNodeInfo) (*option.V2RayTransportOptions, error) {
	ns := relayNodeInfo.NetworkSettings
	if ns == nil {
		return nil, nil
	}

	t := &option.V2RayTransportOptions{Type: ns.Type}
	switch ns.Type {
	case "tcp", "":
		// Mirrors buildTransport on the inbound side: only the http header type
		// is a real transport, and a relay must speak whatever the node it
		// dials is listening for.
		if ns.HeaderType != "http" {
			return nil, nil
		}
		t.Type = "http"
		t.HTTPOptions.Method = ns.Method
		t.HTTPOptions.Path = ns.Path
		t.HTTPOptions.Host = badoption.Listable[string]([]string{ns.Host})
		return t, nil
	case "ws":
		t.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:         ns.Path,
			Headers:      buildHeaders(ns.Host, ns.Headers),
			MaxEarlyData: ns.MaxEarlyData,
		}
		if ns.MaxEarlyData > 0 {
			t.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
	case "grpc":
		t.GRPCOptions = option.V2RayGRPCOptions{ServiceName: ns.ServiceName}
	case "httpupgrade":
		t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Path:    ns.Path,
			Host:    ns.Host,
			Headers: buildHeaders("", ns.Headers),
		}
	default:
		return nil, fmt.Errorf("unsupported relay transport type: %s", ns.Type)
	}
	return t, nil
}

func buildHeaders(host string, extra map[string]string) badoption.HTTPHeader {
	if host == "" && len(extra) == 0 {
		return nil
	}
	headers := badoption.HTTPHeader{}
	if host != "" {
		headers["Host"] = badoption.Listable[string]{host}
	}
	for k, v := range extra {
		headers[k] = badoption.Listable[string]{v}
	}
	return headers
}

func buildRelayTLS(relayNodeInfo *api.RelayNodeInfo) (option.OutboundTLSOptionsContainer, error) {
	ts := relayNodeInfo.TlsSettings
	if ts == nil || !ts.Enabled {
		return option.OutboundTLSOptionsContainer{}, nil
	}

	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: ts.ServerName,
		ALPN:       badoption.Listable[string](ts.Alpn),
	}

	if ts.Type == "reality" && ts.RealityEnabled {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: relayNodeInfo.ServerKey,
		}
		if len(ts.RealityShortID) > 0 {
			tls.Reality.ShortID = ts.RealityShortID[0]
		}
	}

	return option.OutboundTLSOptionsContainer{TLS: tls}, nil
}
