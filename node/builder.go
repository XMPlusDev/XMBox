package node

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/helper/cert"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

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
		listen.TCPFastOpen = nodeInfo.TCPFastOpen
	}
	
	//Multiplex
	var multiplex *option.InboundMultiplexOptions
	if config.Multiplex != nil && config.Multiplex.Enabled {
		multiplex = &option.InboundMultiplexOptions{
			Enabled: config.Multiplex.Enabled,
			Padding: config.Multiplex.Padding,
		}
	}

	// TLS
	var tls option.InboundTLSOptions
	switch nodeInfo.TlsSettings.Type {
	case "tls":
		tls.Enabled = nodeInfo.TlsSettings.Enabled
		tls.ALPN = badoption.Listable[string](nodeInfo.TlsSettings.Alpn)
		certFile, keyFile, err := getCertFile(config.CertConfig, nodeInfo.TlsSettings.CertMode, nodeInfo.TlsSettings.ServerName)
		if err != nil {
			return option.Inbound{}, err
		}
		
		if config.CertConfig != nil {
			switch nodeInfo.TlsSettings.CertMode {
			case "none", "":
			default:
				tls.CertificatePath = certFile
				tls.KeyPath = keyFile
			}
		}
		
		tls.ECH = &option.InboundECHOptions{
			Enabled: nodeInfo.TlsSettings.EnabledECH,
			Key:   nodeInfo.TlsSettings.ECHKey,  
		}
	case "reality":
		tls.Enabled = nodeInfo.TlsSettings.RealityEnabled
		tls.ServerName = nodeInfo.TlsSettings.ServerName
		dest := nodeInfo.TlsSettings.RealityServerName
		if dest == "" {
			dest = tls.ServerName
		}
		tls.Reality = &option.InboundRealityOptions{
			Enabled:    true,
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
		in.Type = "trojan"
		in.Options = trojanOpt

	case "tuic":
		tls.ALPN = append(tls.ALPN, "h3")
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
		}
		in.Type = "hysteria2"
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:              listen,
			IgnoreClientBandwidth:      nodeInfo.NetworkSettings.IgnoreClientBandwidth,
			Obfs:                       obfs,
			BBRProfile:                 nodeInfo.NetworkSettings.BBRProfile,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}

	case "naive":
		in.Type = "naive"
		in.Options = &option.NaiveInboundOptions{
			ListenOptions:              listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}

	case "shadowsocks":
		in.Type = "shadowsocks"
		in.Options = &option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        nodeInfo.NetworkSettings.Cipher,
			Password:      nodeInfo.NetworkSettings.ServerKey,
			Multiplex:     multiplex,
		}

	case "shadowtls":
		ver := 3
		in.Type = "shadowtls"
		in.Options = &option.ShadowTLSInboundOptions{
			ListenOptions: listen,
			Version:       ver,
			StrictMode:    nodeInfo.NetworkSettings.StrictMode,
			Handshake: option.ShadowTLSHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     nodeInfo.NetworkSettings.HandshakeServer,
					ServerPort: nodeInfo.NetworkSettings.HandshakePort,
				},
			},
		}

	case "anytls":
		in.Type = "anytls"
		opts := &option.AnyTLSInboundOptions{
			ListenOptions:              listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
		if len(nodeInfo.NetworkSettings.PaddingScheme) > 0 {
			opts.PaddingScheme = badoption.Listable[string](nodeInfo.NetworkSettings.PaddingScheme)
		}
		in.Options = opts

	default:
		return option.Inbound{}, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return in, nil
}

func getCertFile(certConfig *cert.CertConfig, CertMode string, Domain string) (certFile string, keyFile string, err error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("certConfig is nil")
	}
	
	switch CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("Cert file path or key file path missing, check your config.yml parameters.")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := cert.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := cert.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", CertMode)
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
		return nil, nil

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