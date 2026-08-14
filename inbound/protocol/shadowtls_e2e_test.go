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
)

// stubRouter captures what the inbound routes, standing in for sing-box's real
// router so the test can assert on destination and user.
type stubRouter struct {
	adapter.Router
	routed chan adapter.InboundContext
	echo   bool
}

func (r *stubRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.routed <- metadata
	if r.echo {
		io.Copy(conn, conn)
	}
	conn.Close()
	return nil
}

func (r *stubRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.RouteConnection(ctx, conn, metadata)
}

// tlsHandshakeServer is the real TLS server ShadowTLS camouflages as.
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

// TestShadowTLSEndToEnd drives the inbound exactly as a sing-box client would:
// a shadowsocks client detoured through a shadowtls client.
func TestShadowTLSEndToEnd(t *testing.T) {
	handshakeAddr := tlsHandshakeServer(t)
	handshakeSocks := M.SocksaddrFromNet(handshakeAddr)

	serverKey := randomKey(t, 16)
	userKey := randomKey(t, 16)
	const userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	const userName = "shadowtls_5069_10|user@example.com"

	router := &stubRouter{routed: make(chan adapter.InboundContext, 4)}
	logFactory, err := log.New(log.Options{Options: option.LogOptions{Disabled: false, Level: "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	logger := logFactory.NewLogger("inbound/shadowtls[test]")

	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	in, err := newShadowTLSInbound(context.Background(), router, logger, "test", option.ShadowTLSInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr},
		Version:       3,
		Password:      serverKey,
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

	if err = stls.AddUsers([]ShadowTLSUser{{
		Name:          userName,
		Password:      userUUID,
		InnerPassword: userKey,
	}}); err != nil {
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

	innerMethod, err := shadowaead_2022.NewWithPassword(shadowTLSInnerMethod, serverKey+":"+userKey, nil)
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
		if md.User != userName {
			t.Errorf("user = %q, want %q", md.User, userName)
		}
		t.Logf("routed: destination=%s user=%s inbound=%s", md.Destination, md.User, md.Inbound)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out: nothing was routed")
	}
}
