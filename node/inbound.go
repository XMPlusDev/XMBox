package node

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/cert"
)

// getInboundOptions builds the sing-box Inbound option struct for nodeInfo.
func getInboundOptions(tag string, nodeInfo *api.NodeInfo, config *Config) (option.Inbound, error) {
	addr, err := netip.ParseAddr(nodeInfo.ListenAddr)
	if err != nil {
		return option.Inbound{}, fmt.Errorf("invalid listen IP %q: %w", nodeInfo.ListenAddr, err)
	}

	listen := option.ListenOptions{
		Listen:     (*badoption.Addr)(&addr),
		ListenPort: nodeInfo.ListenPort,
	}
	if nodeInfo.TCPFastOpen {
		listen.TCPFastOpen = true
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
					return option.Inbound{}, err
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
	protocol := strings.ToLower(nodeInfo.Protocol)

	switch protocol {
	case "vmess", "vless":
		transport, err := buildTransport(nodeInfo)
		if err != nil {
			return option.Inbound{}, err
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
		transport, err := buildTransport(nodeInfo)
		if err != nil {
			return option.Inbound{}, err
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
			Method:        nodeInfo.NetworkSettings.Cipher,
			Password:      nodeInfo.ServerKey,
			Multiplex:     multiplex,
			Managed:       true,
		}

	case "shadowtls":
		in.Type = "shadowtls"
		in.Options = &option.ShadowTLSInboundOptions{
			ListenOptions: listen,
			Version:       3,
			StrictMode:    nodeInfo.NetworkSettings.StrictMode,
			Handshake: option.ShadowTLSHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     nodeInfo.NetworkSettings.HandshakeServer,
					ServerPort: nodeInfo.NetworkSettings.HandshakePort,
				},
			},
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
		return option.Inbound{}, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return in, nil
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

func buildTransport(nodeInfo *api.NodeInfo) (*option.V2RayTransportOptions, error) {
	t := &option.V2RayTransportOptions{Type: nodeInfo.NetworkSettings.Type}

	switch nodeInfo.NetworkSettings.Type {
	case "tcp", "":
		if nodeInfo.NetworkSettings.HeaderType == "http" {
			t.Type = "http"
			t.HTTPOptions.Method = nodeInfo.NetworkSettings.Method
			t.HTTPOptions.Path = nodeInfo.NetworkSettings.Path
			t.HTTPOptions.Host = badoption.Listable[string]([]string{nodeInfo.NetworkSettings.Host})
		}
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
		pn :=  certConfig.Provider
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
