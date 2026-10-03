package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xmplusdev/xmbox/api"
)

const testInnerMethod = "2022-blake3-aes-128-gcm"

// detourRouter stands in for sing-box's router. It reproduces the one branch
// that matters here: a connection carrying InboundDetour is injected into the
// named inbound rather than routed, with metadata.Inbound rewritten to the
// detour target (route/route.go:72-87). That rewrite is what keeps traffic
// accounting on the node tag once ShadowTLS fronts a protocol.
type detourRouter struct {
	adapter.Router
	detour adapter.TCPInjectableInbound
	routed chan adapter.InboundContext
}

func (r *detourRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.routed <- metadata
	conn.Close()
	return nil
}

func (r *detourRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	//nolint:staticcheck
	if metadata.InboundDetour != "" {
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		r.detour.NewConnection(ctx, conn, metadata, onClose)
		return
	}
	r.RouteConnection(ctx, conn, metadata)
}

// tlsHandshakeServer is the real TLS server ShadowTLS camouflages as. Its
// certificate is the one the client validates — the node never has one.
func tlsHandshakeServer(t *testing.T) net.Addr {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handshake.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"handshake.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr()
}

func randomKey(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testLogger(t *testing.T, tag string) log.ContextLogger {
	t.Helper()
	factory, err := log.New(log.Options{Options: option.LogOptions{Disabled: false, Level: "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	return factory.NewLogger(tag)
}

// TestShadowTLSEndToEnd drives the chain exactly as a sing-box client would: a
// shadowsocks client detoured through a shadowtls client, reaching a ShadowTLS
// listener that detours into a shadowsocks inbound holding the node tag.
func TestShadowTLSEndToEnd(t *testing.T) {
	handshakeSocks := M.SocksaddrFromNet(tlsHandshakeServer(t))

	serverKey := randomKey(t, 16)
	userKey := randomKey(t, 16)
	const userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	const nodeTag = "shadowtls_5069_10"
	const userName = "shadowtls_5069_10|user@example.com"

	router := &detourRouter{routed: make(chan adapter.InboundContext, 4)}
	logger := testLogger(t, "inbound/shadowtls[test]")
	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))

	// The protocol behind the wrapper: carries the node tag, the destination,
	// the encryption and the user identity.
	innerIn, err := newShadowsocksInbound(context.Background(), router, logger, nodeTag, option.ShadowsocksInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr},
		Method:        testInnerMethod,
		Password:      serverKey,
		Managed:       true,
	})
	if err != nil {
		t.Fatalf("create inner inbound: %v", err)
	}
	inner := innerIn.(*ShadowsocksInbound)
	if err = inner.AddUsers([]option.ShadowsocksUser{{Name: userName, Password: userKey}}); err != nil {
		t.Fatalf("add inner users: %v", err)
	}
	router.detour = inner

	in, err := newShadowTLSInbound(context.Background(), router, logger, api.ShadowTLSTag(nodeTag), option.ShadowTLSInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr, Detour: nodeTag},
		Version:       3,
		Handshake: option.ShadowTLSHandshakeOptions{
			ServerOptions: option.ServerOptions{
				Server:     handshakeSocks.AddrString(),
				ServerPort: handshakeSocks.Port,
			},
		},
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	stls := in.(*ShadowTLSInbound)

	if err = stls.AddUsers([]option.ShadowTLSUser{{Name: userName, Password: userUUID}}); err != nil {
		t.Fatalf("add users: %v", err)
	}
	if err = stls.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { stls.Close() })

	serverAddr := M.SocksaddrFromNet(stls.listener.TCPListener().Addr())

	// Client side: shadowtls tunnel, then the inner shadowsocks layer.
	stdTLS := &tls.Config{ServerName: "handshake.example", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      3,
		Password:     userUUID,
		Server:       serverAddr,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(userUUID, stdTLS),
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("create shadowtls client: %v", err)
	}

	tunnel, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatalf("shadowtls dial: %v", err)
	}
	defer tunnel.Close()

	innerMethod, err := shadowaead_2022.NewWithPassword(testInnerMethod, serverKey+":"+userKey, nil)
	if err != nil {
		t.Fatalf("create inner client method: %v", err)
	}
	target := M.ParseSocksaddr("example.com:443")
	ssConn := innerMethod.DialEarlyConn(tunnel, target)
	if _, err = ssConn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	select {
	case md := <-router.routed:
		if got := md.Destination.String(); got != "example.com:443" {
			t.Errorf("destination = %q, want %q", got, "example.com:443")
		}
		// Without this the connection still flows but is attributed to nobody:
		// no traffic accounting, no limits, no billing.
		if md.User != userName {
			t.Errorf("user = %q, want %q", md.User, userName)
		}
		// The node tag, not the wrapper's — accounting, limiters and connection
		// tracking all key off this.
		if md.Inbound != nodeTag {
			t.Errorf("inbound = %q, want %q", md.Inbound, nodeTag)
		}
		t.Logf("routed: destination=%s user=%s inbound=%s", md.Destination, md.User, md.Inbound)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out: nothing was routed")
	}
}

// TestShadowTLSWithoutDetourIsRejected pins the failure mode that started all
// of this: with no inner protocol there is no destination on the wire, and
// routing the echoed one would send every connection to the listener itself.
func TestShadowTLSWithoutDetourIsRejected(t *testing.T) {
	handshakeSocks := M.SocksaddrFromNet(tlsHandshakeServer(t))
	const userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

	router := &detourRouter{routed: make(chan adapter.InboundContext, 4)}
	logger := testLogger(t, "inbound/shadowtls[nodetour]")
	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))

	in, err := newShadowTLSInbound(context.Background(), router, logger, "nodetour", option.ShadowTLSInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr}, // no Detour
		Version:       3,
		Handshake: option.ShadowTLSHandshakeOptions{
			ServerOptions: option.ServerOptions{
				Server:     handshakeSocks.AddrString(),
				ServerPort: handshakeSocks.Port,
			},
		},
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	stls := in.(*ShadowTLSInbound)
	if err = stls.AddUsers([]option.ShadowTLSUser{{Name: "u", Password: userUUID}}); err != nil {
		t.Fatalf("add users: %v", err)
	}
	if err = stls.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { stls.Close() })

	serverAddr := M.SocksaddrFromNet(stls.listener.TCPListener().Addr())
	stdTLS := &tls.Config{ServerName: "handshake.example", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      3,
		Password:     userUUID,
		Server:       serverAddr,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(userUUID, stdTLS),
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	tunnel, err := client.DialContext(context.Background())
	if err != nil {
		return // refused before the tunnel opened, which is also correct
	}
	defer tunnel.Close()
	_, _ = tunnel.Write([]byte("anything"))

	select {
	case md := <-router.routed:
		t.Fatalf("routed without a detour to %s; nothing on the wire names that destination", md.Destination)
	case <-time.After(2 * time.Second):
	}
}

// A node that is listening but holds no users must refuse rather than accept
// and silently discard — the symptom that made this hard to diagnose.
func TestShadowTLSWithoutUsersRefuses(t *testing.T) {
	handshakeSocks := M.SocksaddrFromNet(tlsHandshakeServer(t))

	router := &detourRouter{routed: make(chan adapter.InboundContext, 4)}
	logger := testLogger(t, "inbound/shadowtls[nousers]")
	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))

	in, err := newShadowTLSInbound(context.Background(), router, logger, "nousers", option.ShadowTLSInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr, Detour: "somewhere"},
		Version:       3,
		Handshake: option.ShadowTLSHandshakeOptions{
			ServerOptions: option.ServerOptions{
				Server:     handshakeSocks.AddrString(),
				ServerPort: handshakeSocks.Port,
			},
		},
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	stls := in.(*ShadowTLSInbound)
	// Creating with no users must not fail: nodes are built before their
	// subscriptions arrive.
	if err = stls.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { stls.Close() })

	conn, err := net.Dial("tcp", stls.listener.TCPListener().Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.ReadAll(conn); err == nil {
		// A closed connection reads EOF with no error, which is the refusal.
		select {
		case md := <-router.routed:
			t.Fatalf("routed %s with no users configured", md.Destination)
		default:
		}
	}
}
