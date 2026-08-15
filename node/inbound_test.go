package node

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/xmplusdev/xmbox/api"
)

// A silent mismap here would change which site the node impersonates, so the
// mapping is pinned rather than assumed.
func TestParseWildcardSNI(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    option.WildcardSNI
		wantErr bool
	}{
		{in: "", want: option.ShadowTLSWildcardSNIOff},
		{in: "off", want: option.ShadowTLSWildcardSNIOff},
		{in: "authed", want: option.ShadowTLSWildcardSNIAuthed},
		{in: "all", want: option.ShadowTLSWildcardSNIAll},
		{in: "  ALL  ", want: option.ShadowTLSWildcardSNIAll},
		{in: "Authed", want: option.ShadowTLSWildcardSNIAuthed},
		{in: "yes", wantErr: true},
		{in: "true", wantErr: true},
	} {
		got, err := parseWildcardSNI(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseWildcardSNI(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseWildcardSNI(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseWildcardSNI(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// inboundNode builds a minimal node, optionally ShadowTLS-fronted.
func inboundNode(cipher, protocol string, shadowTLS *api.ShadowTLSSettings) *api.NodeInfo {
	return &api.NodeInfo{
		Protocol:        protocol,
		ServerKey:       "ZjhmOWMwOWY4ZjE1N2Q2Yg==",
		ListenAddr:      "0.0.0.0",
		ListenPort:      5069,
		NetworkSettings: &api.NetworkSettings{Cipher: cipher, ShadowTLS: shadowTLS},
	}
}

func inboundHandshake() *api.ShadowTLSSettings {
	return &api.ShadowTLSSettings{Version: 3, HandshakeServer: "www.microsoft.com", HandshakePort: 443}
}

// The panel omits "cipher" whenever the node is left on the default, and before
// ShadowTLS became a wrapper its inner cipher was hardcoded — so fronted nodes
// in particular may never have had one configured.
func TestShadowsocksCipherDefault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cipher   string
		protocol string
		want     string
	}{
		{name: "explicit cipher is kept", cipher: "2022-blake3-aes-256-gcm", protocol: "shadowsocks", want: "2022-blake3-aes-256-gcm"},
		{name: "empty falls back", cipher: "", protocol: "shadowsocks", want: defaultShadowsocksCipher},
		{name: "blank falls back", cipher: "   ", protocol: "shadowsocks", want: defaultShadowsocksCipher},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbounds, err := getInboundOptions("node", inboundNode(tc.cipher, tc.protocol, inboundHandshake()), &Config{})
			if err != nil {
				t.Fatalf("getInboundOptions: %v", err)
			}
			if len(inbounds) != 2 {
				t.Fatalf("got %d inbounds, want 2 (protocol + shadowtls front)", len(inbounds))
			}
			opts, ok := inbounds[0].Options.(*option.ShadowsocksInboundOptions)
			if !ok {
				t.Fatalf("inner options are %T, want *option.ShadowsocksInboundOptions", inbounds[0].Options)
			}
			if opts.Method != tc.want {
				t.Errorf("method = %q, want %q", opts.Method, tc.want)
			}
		})
	}
}

// The node tag has to stay on the protocol so accounting keeps working, and the
// front has to detour into it.
func TestShadowTLSChainLayout(t *testing.T) {
	inbounds, err := getInboundOptions("node", inboundNode("2022-blake3-aes-128-gcm", "shadowsocks", inboundHandshake()), &Config{})
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	if inbounds[0].Tag != "node" {
		t.Errorf("protocol tag = %q, want %q", inbounds[0].Tag, "node")
	}
	if inbounds[1].Tag != api.ShadowTLSTag("node") {
		t.Errorf("front tag = %q, want %q", inbounds[1].Tag, api.ShadowTLSTag("node"))
	}
	front, ok := inbounds[1].Options.(*option.ShadowTLSInboundOptions)
	if !ok {
		t.Fatalf("front options are %T, want *option.ShadowTLSInboundOptions", inbounds[1].Options)
	}
	if front.Detour != "node" {
		t.Errorf("detour = %q, want %q", front.Detour, "node")
	}
	if front.ListenPort != 5069 {
		t.Errorf("front listens on %d, want the node's public port 5069", front.ListenPort)
	}
	// The protocol must not hold the public port, or it would be reachable
	// unwrapped alongside the ShadowTLS listener.
	inner := inbounds[0].Options.(*option.ShadowsocksInboundOptions)
	if inner.ListenPort != 0 {
		t.Errorf("protocol listens on %d, want an ephemeral loopback port", inner.ListenPort)
	}
}

// Without ShadowTLS a node stays a single inbound on its public port.
func TestPlainNodeIsSingleInbound(t *testing.T) {
	inbounds, err := getInboundOptions("node", inboundNode("aes-128-gcm", "shadowsocks", nil), &Config{})
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	if len(inbounds) != 1 {
		t.Fatalf("got %d inbounds, want 1", len(inbounds))
	}
	opts := inbounds[0].Options.(*option.ShadowsocksInboundOptions)
	if opts.Method != "aes-128-gcm" {
		t.Errorf("method = %q, want %q", opts.Method, "aes-128-gcm")
	}
	if opts.ListenPort != 5069 {
		t.Errorf("listens on %d, want 5069", opts.ListenPort)
	}
}

// A detoured connection is injected past the V2Ray transport, so a fronted node
// must carry none — otherwise the server would expect an HTTP/ws/grpc layer the
// client never gets to speak.
func TestShadowTLSFrontedNodeHasNoTransport(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			node := inboundNode("", protocol, inboundHandshake())
			node.NetworkSettings.Type = "tcp"
			inbounds, err := getInboundOptions("node", node, &Config{})
			if err != nil {
				t.Fatalf("getInboundOptions: %v", err)
			}
			var transport *option.V2RayTransportOptions
			switch opts := inbounds[0].Options.(type) {
			case *option.VMessInboundOptions:
				transport = opts.Transport
			case *option.VLESSInboundOptions:
				transport = opts.Transport
			case *option.TrojanInboundOptions:
				transport = opts.Transport
			default:
				t.Fatalf("unexpected options type %T", opts)
			}
			if transport != nil {
				t.Errorf("transport = %+v, want nil behind shadowtls", transport)
			}
		})
	}
}

// ws/grpc/httpupgrade cannot work behind ShadowTLS at all, so they are refused
// at creation rather than accepted and then failing every connection.
func TestShadowTLSRejectsV2RayTransports(t *testing.T) {
	for _, transport := range []string{"ws", "grpc", "httpupgrade"} {
		for _, protocol := range []string{"vmess", "vless", "trojan"} {
			node := inboundNode("", protocol, inboundHandshake())
			node.NetworkSettings.Type = transport
			if _, err := getInboundOptions("node", node, &Config{}); err == nil {
				t.Errorf("%s over %s behind shadowtls was accepted, want an error", protocol, transport)
			}
		}
	}
}

// Without ShadowTLS the transport is untouched.
func TestPlainNodeKeepsTransport(t *testing.T) {
	node := inboundNode("", "vmess", nil)
	node.NetworkSettings.Type = "ws"
	inbounds, err := getInboundOptions("node", node, &Config{})
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts := inbounds[0].Options.(*option.VMessInboundOptions)
	if opts.Transport == nil || opts.Transport.Type != "ws" {
		t.Errorf("transport = %+v, want type ws", opts.Transport)
	}
}

// tcp with the http header type is xray's HTTP obfuscation and is a real
// transport; plain tcp is not. Inbound and relay outbound must agree, or a
// relay speaks a layer the node it dials is not listening for.
func TestTCPHTTPHeaderBuildsTransport(t *testing.T) {
	node := inboundNode("", "vmess", nil)
	node.NetworkSettings.Type = "tcp"
	node.NetworkSettings.HeaderType = "http"
	node.NetworkSettings.Path = "/obfs"
	node.NetworkSettings.Host = "example.com"
	node.NetworkSettings.Method = "GET"

	inbounds, err := getInboundOptions("node", node, &Config{})
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	inTransport := inbounds[0].Options.(*option.VMessInboundOptions).Transport
	if inTransport == nil || inTransport.Type != "http" {
		t.Fatalf("inbound transport = %+v, want type http", inTransport)
	}
	if inTransport.HTTPOptions.Path != "/obfs" {
		t.Errorf("inbound path = %q, want %q", inTransport.HTTPOptions.Path, "/obfs")
	}

	relay := &api.RelayNodeInfo{
		NodeType: "vmess", Address: "10.0.0.1", Port: 443,
		NetworkSettings: &api.NetworkSettings{
			Type: "tcp", HeaderType: "http", Path: "/obfs", Host: "example.com", Method: "GET",
		},
	}
	out, err := OutboundRelayBuilder(relay, "relay", &api.SubscriptionInfo{Id: 1, UUID: "u"}, "p")
	if err != nil {
		t.Fatalf("OutboundRelayBuilder: %v", err)
	}
	outTransport := out[0].Options.(*option.VMessOutboundOptions).Transport
	if outTransport == nil || outTransport.Type != "http" {
		t.Fatalf("relay transport = %+v, want type http", outTransport)
	}
	if outTransport.HTTPOptions.Path != inTransport.HTTPOptions.Path {
		t.Errorf("relay path %q does not match inbound %q", outTransport.HTTPOptions.Path, inTransport.HTTPOptions.Path)
	}
}

// A plain tcp node carries no transport on either side.
func TestTCPNodeHasNoTransport(t *testing.T) {
	for _, transportType := range []string{"tcp", ""} {
		for _, headerType := range []string{"none", ""} {
			node := inboundNode("", "vmess", nil)
			node.NetworkSettings.Type = transportType
			node.NetworkSettings.HeaderType = headerType

			inbounds, err := getInboundOptions("node", node, &Config{})
			if err != nil {
				t.Fatalf("getInboundOptions(%q/%q): %v", transportType, headerType, err)
			}
			if got := inbounds[0].Options.(*option.VMessInboundOptions).Transport; got != nil {
				t.Errorf("inbound transport for %q/%q = %+v, want nil", transportType, headerType, got)
			}

			relay := &api.RelayNodeInfo{
				NodeType:        "vmess",
				Address:         "10.0.0.1",
				Port:            443,
				NetworkSettings: &api.NetworkSettings{Type: transportType, HeaderType: headerType},
			}
			out, err := OutboundRelayBuilder(relay, "relay", &api.SubscriptionInfo{Id: 1, UUID: "u"}, "p")
			if err != nil {
				t.Fatalf("OutboundRelayBuilder(%q/%q): %v", transportType, headerType, err)
			}
			if got := out[0].Options.(*option.VMessOutboundOptions).Transport; got != nil {
				t.Errorf("relay transport for %q/%q = %+v, want nil", transportType, headerType, got)
			}
		}
	}
}

// UDP-based protocols cannot be wrapped: ShadowTLS is TCP-only.
func TestShadowTLSRejectsUDPProtocols(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic", "naive"} {
		node := inboundNode("", protocol, inboundHandshake())
		if _, err := getInboundOptions("node", node, &Config{}); err == nil {
			t.Errorf("%s behind shadowtls was accepted, want an error", protocol)
		}
	}
}
