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

// OutboundRelayBuilder builds the outbound chain that relays a single
// subscription's traffic to a downstream node (relayNodeInfo).
//
// Usually one outbound. When the downstream node is fronted by ShadowTLS it is
// two, because a relay is simply a client of that node and has to dial it the
// same way any client would: the protocol outbound keeps the relay tag the
// routing rule points at, and reaches the node through a ShadowTLS outbound.
func OutboundRelayBuilder(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, passwd string) ([]*option.Outbound, error) {
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

	nodeType := strings.ToLower(relayNodeInfo.NodeType)
	var shadowTLS *api.ShadowTLSSettings
	transportType := ""
	if ns := relayNodeInfo.NetworkSettings; ns != nil {
		shadowTLS = ns.ShadowTLS
		transportType = strings.ToLower(ns.Type)
	}

	if shadowTLS != nil {
		if err := checkShadowTLSInner(nodeType, transportType); err != nil {
			return nil, err
		}
	}

	transport, err := buildRelayTransport(relayNodeInfo, shadowTLS != nil)
	if err != nil {
		return nil, err
	}
	tlsContainer, err := buildRelayTLS(relayNodeInfo)
	if err != nil {
		return nil, err
	}
	if shadowTLS != nil {
		// ShadowTLS performs the TLS handshake for this connection; leaving the
		// protocol's own TLS on would nest a second, real TLS session inside
		// the tunnel, which is not what the node is listening for.
		tlsContainer = option.OutboundTLSOptionsContainer{}
	}

	out := &option.Outbound{Tag: RelayOutboundTag(tag, subscription)}

	switch nodeType {
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
		ssOpts := &option.ShadowsocksOutboundOptions{
			ServerOptions: server,
			Method:        shadowsocksCipher(relayNodeInfo.Cipher),
			Password:      passwd,
		}
		if shadowTLS != nil {
			// ShadowTLS is TCP-only, so UDP has to be tunnelled over it.
			// The other protocols carry UDP inside their own stream already.
			ssOpts.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true}
		}
		out.Type = "shadowsocks"
		out.Options = ssOpts

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

	if shadowTLS == nil {
		return []*option.Outbound{out}, nil
	}

	front, err := shadowTLSOutbound(out.Tag, server, subscription.UUID, shadowTLS)
	if err != nil {
		return nil, err
	}
	setRelayDetour(out, front.Tag)
	return []*option.Outbound{out, front}, nil
}

// shadowTLSOutbound builds the ShadowTLS outbound a relay dials through.
func shadowTLSOutbound(relayTag string, server option.ServerOptions, password string, settings *api.ShadowTLSSettings) (*option.Outbound, error) {
	version := settings.Version
	if version == 0 {
		version = 3
	}
	if version != 3 {
		return nil, fmt.Errorf("shadowtls version %d is not supported: only version 3 authenticates users individually", version)
	}
	if settings.HandshakeServer == "" {
		return nil, fmt.Errorf("shadowtls relay needs a handshake_server to present as its TLS server name")
	}
	return &option.Outbound{
		Tag:  api.ShadowTLSTag(relayTag),
		Type: "shadowtls",
		Options: &option.ShadowTLSOutboundOptions{
			ServerOptions: server,
			Version:       version,
			Password:      password,
			// The handshake server, not the node's address: ShadowTLS relays
			// this handshake to that site and hands back its genuine
			// certificate, so it is that name the relay must verify against.
			// TLS is mandatory here — the outbound refuses to build without it.
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: settings.HandshakeServer,
				},
			},
		},
	}, nil
}

// setRelayDetour points a protocol outbound at the ShadowTLS outbound in front
// of it. Detour lives on the embedded DialerOptions, which each protocol's
// options struct carries separately.
func setRelayDetour(out *option.Outbound, detour string) {
	switch opts := out.Options.(type) {
	case *option.VLESSOutboundOptions:
		opts.Detour = detour
	case *option.VMessOutboundOptions:
		opts.Detour = detour
	case *option.TrojanOutboundOptions:
		opts.Detour = detour
	case *option.ShadowsocksOutboundOptions:
		opts.Detour = detour
	case *option.AnyTLSOutboundOptions:
		opts.Detour = detour
	}
}

// buildRelayTransport builds the V2Ray transport a relay speaks to the node it
// dials. fronted reports whether that node is behind ShadowTLS, in which case
// it carries no transport — the node's own inbound drops it too, because a
// detoured connection is injected past the transport layer.
func buildRelayTransport(relayNodeInfo *api.RelayNodeInfo, fronted bool) (*option.V2RayTransportOptions, error) {
	ns := relayNodeInfo.NetworkSettings
	if ns == nil || fronted {
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
