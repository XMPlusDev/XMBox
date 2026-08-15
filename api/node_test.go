package api

import (
	"testing"

	"github.com/bitly/go-simplejson"
)

func parseTransport(t *testing.T, raw string) (*NodeInfo, error) {
	t.Helper()
	data, err := simplejson.NewJson([]byte(raw))
	if err != nil {
		t.Fatalf("bad test json: %v", err)
	}
	node := &NodeInfo{NetworkSettings: &NetworkSettings{}}
	return node, (&Client{}).parseNetworkSettings(data, node)
}

// ShadowTLS is declared as a plug-in on the transport.
func TestParseShadowTLSPlugin(t *testing.T) {
	node, err := parseTransport(t, `{
		"listen_port": 5069,
		"transportProtocol": {
			"type": "tcp",
			"settings": {"header": {"type": "none"}},
			"plug-in": {
				"name": "shadowtls",
				"handshake_server": "www.microsoft.com",
				"handshake_server_port": 443,
				"strict_mode": false,
				"wildcard_sni": "off"
			}
		}
	}`)
	if err != nil {
		t.Fatalf("parseNetworkSettings: %v", err)
	}
	st := node.NetworkSettings.ShadowTLS
	if st == nil {
		t.Fatal("ShadowTLS is nil, want the plug-in to enable it")
	}
	if st.HandshakeServer != "www.microsoft.com" {
		t.Errorf("handshake server = %q, want www.microsoft.com", st.HandshakeServer)
	}
	if st.HandshakePort != 443 {
		t.Errorf("handshake port = %d, want 443", st.HandshakePort)
	}
	if st.Version != 3 {
		t.Errorf("version = %d, want 3 by default", st.Version)
	}
	if st.WildcardSNI != "off" {
		t.Errorf("wildcard sni = %q, want off", st.WildcardSNI)
	}
}

// Only tcp can carry it, and a non-tcp transport is refused rather than quietly
// dropping the wrapper — that would leave the node listening unwrapped.
func TestParseShadowTLSPluginRejectsNonTCP(t *testing.T) {
	for _, transport := range []string{"ws", "grpc", "httpupgrade"} {
		_, err := parseTransport(t, `{
			"listen_port": 5069,
			"transportProtocol": {
				"type": "`+transport+`",
				"settings": {"path": "/x"},
				"plug-in": {"name": "shadowtls", "handshake_server": "www.microsoft.com"}
			}
		}`)
		if err == nil {
			t.Errorf("%s with a shadowtls plug-in was accepted, want an error", transport)
		}
	}
}

// A plug-in naming something else leaves ShadowTLS off.
func TestParseUnknownPluginIgnored(t *testing.T) {
	node, err := parseTransport(t, `{
		"listen_port": 5069,
		"transportProtocol": {
			"type": "tcp",
			"settings": {"header": {"type": "none"}},
			"plug-in": {"name": "something-else"}
		}
	}`)
	if err != nil {
		t.Fatalf("parseNetworkSettings: %v", err)
	}
	if node.NetworkSettings.ShadowTLS != nil {
		t.Error("ShadowTLS was enabled by an unrelated plug-in")
	}
}

// Node records written before the move keep working.
func TestParseLegacyShadowTLSShapes(t *testing.T) {
	for name, raw := range map[string]string{
		"top-level object": `{
			"listen_port": 5069,
			"transportProtocol": {"type": "tcp", "settings": {}},
			"shadowtls": {"handshake_server": "www.microsoft.com", "handshake_server_port": 443}
		}`,
		"flat keys": `{
			"listen_port": 5069,
			"transportProtocol": {"type": "tcp", "settings": {}},
			"handshake_server": "www.microsoft.com",
			"handshake_server_port": 443
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			node, err := parseTransport(t, raw)
			if err != nil {
				t.Fatalf("parseNetworkSettings: %v", err)
			}
			if node.NetworkSettings.ShadowTLS == nil {
				t.Fatal("ShadowTLS is nil, want the legacy shape honoured")
			}
			if node.NetworkSettings.ShadowTLS.HandshakeServer != "www.microsoft.com" {
				t.Errorf("handshake server = %q", node.NetworkSettings.ShadowTLS.HandshakeServer)
			}
		})
	}
}

// A node with no plug-in is not fronted.
func TestParseNoPlugin(t *testing.T) {
	node, err := parseTransport(t, `{
		"listen_port": 5069,
		"transportProtocol": {"type": "tcp", "settings": {"header": {"type": "none"}}}
	}`)
	if err != nil {
		t.Fatalf("parseNetworkSettings: %v", err)
	}
	if node.NetworkSettings.ShadowTLS != nil {
		t.Error("ShadowTLS was enabled without a plug-in")
	}
}
