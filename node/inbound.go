package node

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/cert"
)

// ShadowTLSTag returns the tag of the ShadowTLS listener fronting a node.
//
// The node tag stays on the protocol inbound behind it, so traffic accounting,
// limiters and connection tracking — all keyed on metadata.Inbound, which the
// router rewrites to the detour target — keep working unchanged.

// getInboundOptions builds the sing-box inbound chain for nodeInfo.
//
// A node is normally a single inbound. When ShadowTLS is enabled it becomes
// two: the node's real protocol bound to loopback keeping the node tag, fronted
// by a ShadowTLS listener on the public port that detours into it. ShadowTLS
// carries no destination and no encryption of its own, so the protocol behind
// it is what actually moves traffic.
func getInboundOptions(tag string, nodeInfo *api.NodeInfo, config *Config) ([]option.Inbound, error) {
	addr, err := netip.ParseAddr(nodeInfo.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen IP %q: %w", nodeInfo.ListenAddr, err)
	}

	listen := option.ListenOptions{
		Listen:     (*badoption.Addr)(&addr),
		ListenPort: nodeInfo.ListenPort,
	}
	if nodeInfo.TCPFastOpen {
		listen.TCPFastOpen = true
	}

	protocol := strings.ToLower(nodeInfo.Protocol)
	shadowTLS := nodeInfo.NetworkSettings.ShadowTLS

	// A node whose protocol is itself "shadowtls" predates the wrapper being an
	// option on any protocol. It always meant shadowsocks behind ShadowTLS, so
	// it is expressed that way now.
	if protocol == "shadowtls" {
		if shadowTLS == nil {
			return nil, fmt.Errorf("shadowtls node %q has no handshake settings", tag)
		}
		protocol = "shadowsocks"
	}

	publicListen := listen
	if shadowTLS != nil {
		if err := checkShadowTLSInner(protocol, strings.ToLower(nodeInfo.NetworkSettings.Type)); err != nil {
			return nil, err
		}
		// The protocol moves to loopback on an ephemeral port; it is reached by
		// injection through the detour, never over its own listener.
		loopback := netip.MustParseAddr("127.0.0.1")
		listen = option.ListenOptions{Listen: (*badoption.Addr)(&loopback), ListenPort: 0}
		// ShadowTLS already performs the TLS handshake. Leaving the protocol's
		// own TLS on would nest a second, real TLS session inside the tunnel.
		nodeInfo.TlsSettings = nil
	}

	// Multiplex
	var multiplex *option.InboundMultiplexOptions
	if config.InstanceConfig != nil && config.InstanceConfig.MultiplexConfig != nil && config.InstanceConfig.MultiplexConfig.Enabled {
		multiplex = &option.InboundMultiplexOptions{
			Enabled: config.InstanceConfig.MultiplexConfig.Enabled,
			Padding: config.InstanceConfig.MultiplexConfig.Padding,
		}
	}

	// TLS
	var tls option.InboundTLSOptions
	if nodeInfo.TlsSettings != nil {
		switch nodeInfo.TlsSettings.Type {
		case "tls":
			tls.Enabled = nodeInfo.TlsSettings.Enabled
			tls.ALPN = badoption.Listable[string](nodeInfo.TlsSettings.Alpn)
			if config.CertConfig != nil && nodeInfo.TlsSettings.CertMode != "none" {
				certFile, keyFile, err := getCertFile(config.CertConfig, nodeInfo.TlsSettings)
				if err != nil {
					return nil, err
				}
				tls.CertificatePath = certFile
				tls.KeyPath = keyFile
			}
			if len(nodeInfo.TlsSettings.ECHKey) > 0 {
				tls.ECH = &option.InboundECHOptions{
					Enabled: nodeInfo.TlsSettings.EnabledECH,
					Key:     nodeInfo.TlsSettings.ECHKey,
				}
			}
		case "reality":
			tls.Enabled = nodeInfo.TlsSettings.Enabled
			tls.ServerName = nodeInfo.TlsSettings.ServerName
			dest := nodeInfo.TlsSettings.RealityServerName
			if dest == "" {
				dest = tls.ServerName
			}
			tls.Reality = &option.InboundRealityOptions{
				Enabled:    nodeInfo.TlsSettings.RealityEnabled,
				ShortID:    badoption.Listable[string](nodeInfo.TlsSettings.RealityShortID),
				PrivateKey: nodeInfo.TlsSettings.RealityPrivateKey,
				Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     dest,
						ServerPort: nodeInfo.TlsSettings.RealityServerPort,
					},
				},
			}
		}
	}

	in := option.Inbound{Tag: tag}

	switch protocol {
	case "vmess", "vless":
		transport, err := buildTransport(nodeInfo, shadowTLS != nil)
		if err != nil {
			return nil, err
		}
		tlsContainer := option.InboundTLSOptionsContainer{TLS: &tls}
		if protocol == "vless" {
			in.Type = "vless"
			in.Options = &option.VLESSInboundOptions{
				ListenOptions:              listen,
				InboundTLSOptionsContainer: tlsContainer,
				Transport:                  transport,
				Multiplex:                  multiplex,
			}
		} else {
			in.Type = "vmess"
			in.Options = &option.VMessInboundOptions{
				ListenOptions:              listen,
				InboundTLSOptionsContainer: tlsContainer,
				Transport:                  transport,
				Multiplex:                  multiplex,
			}
		}

	case "trojan":
		transport, err := buildTransport(nodeInfo, shadowTLS != nil)
		if err != nil {
			return nil, err
		}
		trojanOpt := &option.TrojanInboundOptions{
			ListenOptions:              listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
			Transport:                  transport,
			Multiplex:                  multiplex,
		}
		// Apply fallback config from the panel API
		applyTrojanFallback(trojanOpt, nodeInfo.FallbackConfig)
		in.Type = "trojan"
		in.Options = trojanOpt

	case "tuic":
		cc := nodeInfo.NetworkSettings.CongestionControl
		if cc == "" {
			cc = "bbr"
		}
		in.Type = "tuic"
		in.Options = &option.TUICInboundOptions{
			ListenOptions:              listen,
			CongestionControl:          cc,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}

	case "hysteria2":
		var obfs *option.Hysteria2Obfs
		if nodeInfo.NetworkSettings.ObfsType != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     nodeInfo.NetworkSettings.ObfsType,
				Password: nodeInfo.NetworkSettings.ObfsPasswd,
			}
			if nodeInfo.NetworkSettings.ObfsType == "gecko" {
				obfs.GeckoOptions = option.Hysteria2ObfsGecko{
					MinPacketSize: nodeInfo.NetworkSettings.GeckoMinPacketSize,
					MaxPacketSize: nodeInfo.NetworkSettings.GeckoMaxPacketSize,
				}
			}
		}
		var realm *option.Hysteria2InboundRealm
		if nodeInfo.NetworkSettings.RealmServerURL != "" {
			realm = &option.Hysteria2InboundRealm{
				Hysteria2Realm: option.Hysteria2Realm{
					ServerURL: nodeInfo.NetworkSettings.RealmServerURL,
					Token:     nodeInfo.NetworkSettings.RealmToken,
					RealmID:   nodeInfo.NetworkSettings.RealmID,
				},
			}
			if len(nodeInfo.NetworkSettings.RealmSTUNServers) > 0 {
				realm.STUNServers = badoption.Listable[string](nodeInfo.NetworkSettings.RealmSTUNServers)
			}
		}
		in.Type = "hysteria2"
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:              listen,
			IgnoreClientBandwidth:      nodeInfo.NetworkSettings.IgnoreClientBandwidth,
			Obfs:                       obfs,
			BBRProfile:                 nodeInfo.NetworkSettings.BBRProfile,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
			Realm:                      realm,
		}

	case "naive":
		in.Type = "naive"
		in.Options = &option.NaiveInboundOptions{
			ListenOptions:              listen,
			QUICCongestionControl:      nodeInfo.NetworkSettings.QUICCongestionControl,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}

	case "shadowsocks":
		in.Type = "shadowsocks"
		in.Options = &option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        shadowsocksCipher(nodeInfo.NetworkSettings.Cipher),
			Password:      nodeInfo.ServerKey,
			Multiplex:     multiplex,
			Managed:       true,
		}

	case "anytls":
		opts := &option.AnyTLSInboundOptions{
			ListenOptions:              listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
		if len(nodeInfo.NetworkSettings.PaddingScheme) > 0 {
			opts.PaddingScheme = badoption.Listable[string](nodeInfo.NetworkSettings.PaddingScheme)
		}
		in.Type = "anytls"
		in.Options = opts

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if shadowTLS == nil {
		return []option.Inbound{in}, nil
	}
	front, err := shadowTLSInbound(tag, publicListen, shadowTLS)
	if err != nil {
		return nil, err
	}
	// Protocol first: the router resolves the detour per connection, but
	// creating the target first means it is never briefly missing.
	return []option.Inbound{in, front}, nil
}

// shadowTLSInbound builds the ShadowTLS listener fronting a node, detouring
// into the protocol inbound that holds the node tag.
func shadowTLSInbound(tag string, listen option.ListenOptions, settings *api.ShadowTLSSettings) (option.Inbound, error) {
	wildcardSNI, err := parseWildcardSNI(settings.WildcardSNI)
	if err != nil {
		return option.Inbound{}, err
	}
	version := settings.Version
	if version == 0 {
		version = 3
	}
	if version != 3 {
		return option.Inbound{}, fmt.Errorf("shadowtls version %d is not supported: only version 3 authenticates users individually", version)
	}
	if settings.HandshakeServer == "" && wildcardSNI == option.ShadowTLSWildcardSNIOff {
		return option.Inbound{}, fmt.Errorf("shadowtls needs a handshake_server unless wildcard_sni is enabled")
	}
	port := settings.HandshakePort
	if port == 0 {
		port = 443
	}
	listen.Detour = tag
	return option.Inbound{
		Tag:  api.ShadowTLSTag(tag),
		Type: "shadowtls",
		Options: &option.ShadowTLSInboundOptions{
			ListenOptions: listen,
			Version:       version,
			StrictMode:    settings.StrictMode,
			WildcardSNI:   wildcardSNI,
			Handshake: option.ShadowTLSHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     settings.HandshakeServer,
					ServerPort: port,
				},
			},
		},
	}, nil
}

// defaultShadowsocksCipher is used when the panel sends no cipher.
//
// It mirrors the panel's own fallback so the two ends cannot disagree:
// Server::cipher() defaults to this, and the server_key it derives alongside is
// 16 bytes, which is this cipher's key length. Nodes fronted by ShadowTLS
// depend on it most — before ShadowTLS became a wrapper its inner cipher was
// hardcoded, so those nodes never needed one configured.
const defaultShadowsocksCipher = "2022-blake3-aes-128-gcm"

// shadowsocksCipher returns the configured cipher, or the shared default.
func shadowsocksCipher(cipher string) string {
	if cipher = strings.TrimSpace(cipher); cipher != "" {
		return cipher
	}
	return defaultShadowsocksCipher
}

// checkShadowTLSInner reports whether protocol over transport can sit behind
// ShadowTLS.
//
// Three things rule combinations out. ShadowTLS is TCP-only, so QUIC-based
// protocols cannot be wrapped at all. A detoured connection is injected
// straight into the protocol's service and never passes through its V2Ray
// transport — VMessInbound.NewConnection reaches h.service directly and never
// touches h.transport — so ws, grpc and httpupgrade would be spoken by the
// client and never read by the server. And protocols that rely on TLS for
// their encryption travel in cleartext behind ShadowTLS, which provides none;
// those are warned about rather than refused.
func checkShadowTLSInner(protocol, transport string) error {
	// A fronted node's connections arrive by injection through the detour,
	// which bypasses the V2Ray transport entirely — VMessInbound.NewConnection
	// reaches h.service directly and never touches h.transport — so ws, grpc
	// and httpupgrade would be spoken by the client and never read here.
	if transport != "" && transport != "tcp" {
		return fmt.Errorf("shadowtls needs the tcp transport, got %s: a detoured connection is injected past the transport, so the %s layer would never be read", transport, transport)
	}
	switch protocol {
	case "shadowsocks", "vmess":
		return nil
	case "vless", "trojan", "anytls":
		log.Printf("warning: %s relies on TLS for encryption and ShadowTLS provides none; traffic behind it travels in cleartext", protocol)
		return nil
	case "hysteria", "hysteria2", "tuic", "naive":
		return fmt.Errorf("%s cannot run behind shadowtls: it needs UDP and shadowtls is TCP-only", protocol)
	default:
		return fmt.Errorf("%s cannot run behind shadowtls", protocol)
	}
}

// applyTrojanFallback sets the default Fallback on a TrojanInboundOptions
// from the panel's single fallback object {Server, ServerPort}.
func applyTrojanFallback(opts *option.TrojanInboundOptions, fallback *api.FallbackConfig) {
	if fallback == nil || fallback.Server == "" || fallback.ServerPort == 0 {
		return
	}
	opts.Fallback = &option.ServerOptions{
		Server:     fallback.Server,
		ServerPort: fallback.ServerPort,
	}
}

// buildTransport builds the V2Ray transport for a node.
//
// fronted reports whether ShadowTLS sits in front. A fronted node must carry no
// transport at all: its connections arrive by injection through the detour,
// which bypasses the transport layer entirely. checkShadowTLSInner has already
// refused the transports that genuinely need one.
func buildTransport(nodeInfo *api.NodeInfo, fronted bool) (*option.V2RayTransportOptions, error) {
	if fronted {
		return nil, nil
	}
	t := &option.V2RayTransportOptions{Type: nodeInfo.NetworkSettings.Type}

	switch nodeInfo.NetworkSettings.Type {
	case "tcp", "":
		// Only the http header type is a real transport — xray's
		// "tcp + header.type: http" obfuscation, which sing-box models as the
		// v2ray http transport. A plain TCP node carries none; building one
		// unconditionally left the server waiting for an HTTP layer no client
		// sends.
		if nodeInfo.NetworkSettings.HeaderType != "http" {
			return nil, nil
		}
		t.Type = "http"
		t.HTTPOptions.Method = nodeInfo.NetworkSettings.Method
		t.HTTPOptions.Path = nodeInfo.NetworkSettings.Path
		t.HTTPOptions.Host = badoption.Listable[string]([]string{nodeInfo.NetworkSettings.Host})
		return t, nil
	case "ws":
		t.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:                nodeInfo.NetworkSettings.Path,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			MaxEarlyData:        nodeInfo.NetworkSettings.MaxEarlyData,
		}
	case "grpc":
		t.GRPCOptions = option.V2RayGRPCOptions{ServiceName: nodeInfo.NetworkSettings.ServiceName}
	case "httpupgrade":
		t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Path: nodeInfo.NetworkSettings.Path,
			Host: nodeInfo.NetworkSettings.Host,
		}
	}
	return t, nil
}

func getCertFile(certConfig *cert.CertConfig, tlsSettings *api.TlsSettings) (certFile string, keyFile string, err error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("certConfig is nil")
	}
	switch tlsSettings.CertMode {
	case "file":
		cf := certConfig.CertFile
		kf := certConfig.KeyFile
		if tlsSettings != nil && tlsSettings.CertFile != "" {
			cf = tlsSettings.CertFile
		}
		if tlsSettings != nil && tlsSettings.KeyFile != "" {
			kf = tlsSettings.KeyFile
		}
		if cf == "" || kf == "" {
			return "", "", fmt.Errorf("cert file path or key file path missing")
		}
		return cf, kf, nil
	case "dns":
		pn := certConfig.Provider
		if tlsSettings != nil {
			pn = tlsSettings.DnsProvider
		}
		if pn == "" {
			return "", "", fmt.Errorf("cert dns provider name is required")
		}
		lego, err := cert.NewForNode(certConfig, pn)
		if err != nil {
			return "", "", err
		}
		return lego.DNSCert(tlsSettings.CertMode, tlsSettings.CertDomainName, tlsSettings.CertEmail)
	case "http", "tls":
		lego, err := cert.New(certConfig)
		if err != nil {
			return "", "", err
		}
		return lego.HTTPCert(tlsSettings.CertMode, tlsSettings.CertDomainName, tlsSettings.CertEmail)
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", tlsSettings.CertMode)
	}
}

// parseWildcardSNI maps the panel's wildcard_sni string onto sing-box's enum.
// option.WildcardSNI only decodes from JSON, so the mapping is spelled out
// here; an unrecognised value is rejected rather than silently treated as off,
// since that would quietly change which site the node impersonates.
func parseWildcardSNI(value string) (option.WildcardSNI, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off":
		return option.ShadowTLSWildcardSNIOff, nil
	case "authed":
		return option.ShadowTLSWildcardSNIAuthed, nil
	case "all":
		return option.ShadowTLSWildcardSNIAll, nil
	default:
		return option.ShadowTLSWildcardSNIOff, fmt.Errorf("unknown wildcard_sni %q: want off, authed, or all", value)
	}
}
