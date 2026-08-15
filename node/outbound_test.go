package node

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/xmplusdev/xmbox/api"
)

func relayNode(nodeType, transport string, shadowTLS *api.ShadowTLSSettings) *api.RelayNodeInfo {
	return &api.RelayNodeInfo{
		NodeType:        nodeType,
		Address:         "node.example.com",
		Port:            5069,
		Cipher:          "2022-blake3-aes-128-gcm",
		NetworkSettings: &api.NetworkSettings{Type: transport, ShadowTLS: shadowTLS},
		TlsSettings:     &api.TlsSettings{Type: "tls", Enabled: true, ServerName: "node.example.com"},
	}
}

func handshake() *api.ShadowTLSSettings {
	return &api.ShadowTLSSettings{Version: 3, HandshakeServer: "www.microsoft.com", HandshakePort: 443}
}

// A relay is a client of the node it dials, so a ShadowTLS-fronted target has
// to be reached the same way any client reaches it: the protocol detouring
// through a ShadowTLS outbound.
func TestRelayShadowTLSChain(t *testing.T) {
	sub := &api.SubscriptionInfo{Id: 7, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811"}
	outbounds, err := OutboundRelayBuilder(relayNode("shadowsocks", "tcp", handshake()), "relay", sub, "key:userkey")
	if err != nil {
		t.Fatalf("OutboundRelayBuilder: %v", err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("got %d outbounds, want 2", len(outbounds))
	}

	protocolTag := RelayOutboundTag("relay", sub)
	if outbounds[0].Tag != protocolTag {
		t.Errorf("protocol tag = %q, want %q — the routing rule points at it", outbounds[0].Tag, protocolTag)
	}
	if outbounds[1].Tag != api.ShadowTLSTag(protocolTag) {
		t.Errorf("front tag = %q, want %q", outbounds[1].Tag, api.ShadowTLSTag(protocolTag))
	}

	ss, ok := outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if !ok {
		t.Fatalf("protocol options are %T", outbounds[0].Options)
	}
	if ss.Detour != outbounds[1].Tag {
		t.Errorf("detour = %q, want %q", ss.Detour, outbounds[1].Tag)
	}
	if ss.UDPOverTCP == nil || !ss.UDPOverTCP.Enabled {
		t.Error("udp_over_tcp is off; shadowtls is TCP-only so UDP would not survive")
	}

	front, ok := outbounds[1].Options.(*option.ShadowTLSOutboundOptions)
	if !ok {
		t.Fatalf("front options are %T", outbounds[1].Options)
	}
	if front.TLS == nil || !front.TLS.Enabled {
		t.Fatal("front TLS is off; the shadowtls outbound refuses to build without it")
	}
	// The certificate comes from the handshake server, relayed through the
	// node, so verifying against the node's address could never succeed.
	if front.TLS.ServerName != "www.microsoft.com" {
		t.Errorf("server name = %q, want the handshake server", front.TLS.ServerName)
	}
	if front.Password != sub.UUID {
		t.Errorf("password = %q, want the subscription UUID the node registered", front.Password)
	}
}

// The protocol's own TLS and transport are dropped behind ShadowTLS, matching
// what the node's inbound does.
func TestRelayShadowTLSDropsInnerTLSAndTransport(t *testing.T) {
	sub := &api.SubscriptionInfo{Id: 1, UUID: "uuid"}
	outbounds, err := OutboundRelayBuilder(relayNode("vmess", "tcp", handshake()), "relay", sub, "")
	if err != nil {
		t.Fatalf("OutboundRelayBuilder: %v", err)
	}
	opts := outbounds[0].Options.(*option.VMessOutboundOptions)
	if opts.TLS != nil && opts.TLS.Enabled {
		t.Error("inner TLS is enabled; that would nest a second real TLS session inside the tunnel")
	}
	if opts.Transport != nil {
		t.Errorf("inner transport = %+v, want nil", opts.Transport)
	}
}

// ShadowTLS is a transport plug-in, not a protocol, so nothing answers to it as
// a node type.
func TestRelayShadowTLSIsNotANodeType(t *testing.T) {
	sub := &api.SubscriptionInfo{Id: 1, UUID: "uuid"}
	if _, err := OutboundRelayBuilder(relayNode("shadowtls", "tcp", handshake()), "relay", sub, "key:userkey"); err == nil {
		t.Error("a relay node typed shadowtls was accepted, want unsupported")
	}
}

// Without ShadowTLS a relay stays a single outbound with no detour.
func TestRelayPlainNode(t *testing.T) {
	sub := &api.SubscriptionInfo{Id: 1, UUID: "uuid"}
	outbounds, err := OutboundRelayBuilder(relayNode("shadowsocks", "tcp", nil), "relay", sub, "pw")
	if err != nil {
		t.Fatalf("OutboundRelayBuilder: %v", err)
	}
	if len(outbounds) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(outbounds))
	}
	if got := outbounds[0].Options.(*option.ShadowsocksOutboundOptions).Detour; got != "" {
		t.Errorf("detour = %q, want empty", got)
	}
}

// The same combinations the inbound refuses are refused here, or the relay
// would speak a layer the node it dials is not listening for.
func TestRelayShadowTLSRejectsBadCombinations(t *testing.T) {
	sub := &api.SubscriptionInfo{Id: 1, UUID: "uuid"}
	for _, transport := range []string{"ws", "grpc", "httpupgrade"} {
		if _, err := OutboundRelayBuilder(relayNode("vmess", transport, handshake()), "relay", sub, ""); err == nil {
			t.Errorf("vmess over %s behind shadowtls was accepted", transport)
		}
	}
	for _, nodeType := range []string{"hysteria2", "tuic", "naive"} {
		if _, err := OutboundRelayBuilder(relayNode(nodeType, "tcp", handshake()), "relay", sub, ""); err == nil {
			t.Errorf("%s behind shadowtls was accepted", nodeType)
		}
	}
	missing := &api.ShadowTLSSettings{Version: 3}
	if _, err := OutboundRelayBuilder(relayNode("shadowsocks", "tcp", missing), "relay", sub, "pw"); err == nil {
		t.Error("a relay with no handshake_server was accepted; its TLS name would be unverifiable")
	}
}
