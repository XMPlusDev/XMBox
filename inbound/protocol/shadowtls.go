package protocol

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// shadowTLSInnerMethod is the cipher of the inner shadowsocks layer. ShadowTLS
// v3 authenticates users and frames the stream as TLS records, but it does not
// encrypt the payload — verifiedConn.write puts the bytes on the wire verbatim
// behind a record header and an HMAC. Encrypting the inner layer is what keeps
// the destination address and the traffic itself off the wire in cleartext, and
// what makes the stream actually resemble the TLS it is imitating.
const shadowTLSInnerMethod = "2022-blake3-aes-128-gcm"

// ShadowTLSUser pairs a subscription's outer ShadowTLS credential with its key
// for the inner shadowsocks layer. Both halves are per-user on purpose: the
// outer one authenticates the connection, and the inner one keeps a user's
// traffic unreadable to every *other* user, since session keys derive from the
// per-user PSK (shadowaead_2022/service_multi.go:177) rather than from the
// node-wide identity key.
type ShadowTLSUser struct {
	Name          string
	Password      string
	InnerPassword string
}

// ShadowTLSInbound is a full sing-box ShadowTLS inbound with zero-downtime
// user management. The shadowtls.Service is recreated and swapped atomically
// on user changes — the listener and TLS layer never restart.
//
// Connection-safety guarantee: existing connections are NEVER closed when users
// are removed.  shadowtls.Service has no UpdateUsers method, so we rebuild a
// new service object and atomically swap the pointer.  Goroutines that are
// mid-handshake on the OLD service continue running to completion: they hold a
// reference to the old service via closure, keeping it alive in the GC until
// all those goroutines finish.  After the handshake, the routed connection is
// owned by the router goroutine — entirely independent of whichever service
// pointer h.service currently holds.
type ShadowTLSInbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener

	// inner decrypts the tunnelled stream and parses the destination out of it.
	// ShadowTLS is a TLS-camouflage transport and carries no destination of its
	// own — shadowtls.Service hands the handler back whatever destination it was
	// given, which for a plain TCP listener is this node's own listen address.
	// The real target comes from the shadowsocks header the client's inner
	// shadowsocks outbound writes inside the tunnel.
	inner shadowsocks.MultiService[int]

	// service is swapped atomically on user changes
	service atomic.Pointer[shadowtls.Service]

	// base config — everything except Users; used to recreate the service
	mu              sync.Mutex
	users           []ShadowTLSUser
	baseVersion     int
	baseHandshake   shadowtls.HandshakeConfig
	baseHSForSNI    map[string]shadowtls.HandshakeConfig
	baseStrictMode  bool
	baseWildcardSNI shadowtls.WildcardSNI
}

// RegisterShadowTLS overrides the built-in ShadowTLS factory in registry.
func RegisterShadowTLS(registry *inbound.Registry) {
	inbound.Register[option.ShadowTLSInboundOptions](registry, C.TypeShadowTLS, newShadowTLSInbound)
}

func newShadowTLSInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.ShadowTLSInboundOptions,
) (adapter.Inbound, error) {
	h := &ShadowTLSInbound{
		Adapter: inbound.NewAdapter(C.TypeShadowTLS, tag),
		// uot.NewRouter adds UDP-over-TCP support — the only way UDP reaches a
		// TCP-only transport like ShadowTLS.
		router: uot.NewRouter(router, logger),
		logger: logger,
	}
	if options.Version == 0 {
		options.Version = 1
	}
	if options.Version != 3 {
		return nil, E.New("unsupported shadowtls version: ", options.Version, " (only version 3 provides per-user authentication)")
	}
	h.baseVersion = options.Version
	h.baseStrictMode = options.StrictMode
	h.baseWildcardSNI = shadowtls.WildcardSNI(options.WildcardSNI)

	// options.Password carries the inner shadowsocks identity key (iPSK), not a
	// ShadowTLS secret: under v3 every client is authenticated by its own entry
	// in Users, and sing-shadowtls reads ServiceConfig.Password only on the v2
	// path (service.go:146). node/inbound.go fills it from the node's ServerKey.
	// Per-user keys are layered on top of it by rebuildInner.
	innerService, err := shadowaead_2022.NewMultiServiceWithPassword[int](
		shadowTLSInnerMethod,
		options.Password,
		int64(C.UDPTimeout.Seconds()),
		adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, h.newConnection, h.newPacketConnection, h),
		ntp.TimeFuncFromContext(ctx),
	)
	if err != nil {
		return nil, E.Cause(err, "create inner shadowsocks service (", shadowTLSInnerMethod, " needs a base64 key of 16 bytes or more; longer keys are derived down)")
	}
	h.inner = innerService

	// Users carry two secrets and inbound options can only express one, so they
	// have to arrive through AddUsers. XMBox always creates nodes empty and
	// fills them from the subscription list.
	if len(options.Users) > 0 {
		return nil, E.New("shadowtls users cannot be set in inbound options: the inner shadowsocks key has no field there")
	}

	var handshakeForServerName map[string]shadowtls.HandshakeConfig
	if options.Version > 1 {
		handshakeForServerName = make(map[string]shadowtls.HandshakeConfig)
		if options.HandshakeForServerName != nil {
			for _, entry := range options.HandshakeForServerName.Entries() {
				d, err := dialer.New(ctx, entry.Value.DialerOptions, entry.Value.ServerIsDomain())
				if err != nil {
					return nil, err
				}
				handshakeForServerName[entry.Key] = shadowtls.HandshakeConfig{
					Server: entry.Value.ServerOptions.Build(),
					Dialer: d,
				}
			}
		}
	}
	h.baseHSForSNI = handshakeForServerName

	serverIsDomain := options.Handshake.ServerIsDomain()
	if options.WildcardSNI != option.ShadowTLSWildcardSNIOff {
		serverIsDomain = true
	}
	handshakeDialer, err := dialer.New(ctx, options.Handshake.DialerOptions, serverIsDomain)
	if err != nil {
		return nil, err
	}
	h.baseHandshake = shadowtls.HandshakeConfig{
		Server: options.Handshake.ServerOptions.Build(),
		Dialer: handshakeDialer,
	}

	// Starts with no users, so this parks a nil service until AddUsers runs.
	if err := h.rebuildService(); err != nil {
		return nil, err
	}

	h.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: h,
	})
	return h, nil
}

func (h *ShadowTLSInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *ShadowTLSInbound) Close() error {
	return h.listener.Close()
}

// ─── hot user management ─────────────────────────────────────────────────────

// AddUsers upserts users by Name across both layers.
func (h *ShadowTLSInbound) AddUsers(users []ShadowTLSUser) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := make(map[string]int, len(h.users))
	for i, u := range h.users {
		idx[u.Name] = i
	}
	for _, u := range users {
		if i, ok := idx[u.Name]; ok {
			h.users[i] = u
		} else {
			idx[u.Name] = len(h.users)
			h.users = append(h.users, u)
		}
	}
	return h.rebuild()
}

// DelUsers removes users by Name from both layers.
func (h *ShadowTLSInbound) DelUsers(names []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	del := make(map[string]struct{}, len(names))
	for _, n := range names {
		del[n] = struct{}{}
	}
	remaining := h.users[:0]
	for _, u := range h.users {
		if _, ok := del[u.Name]; !ok {
			remaining = append(remaining, u)
		}
	}
	h.users = remaining
	return h.rebuild()
}

// rebuild republishes the current user list to both layers. Caller must hold
// h.mu. The inner layer is updated first so that a user is never accepted by
// ShadowTLS before its key can decrypt the stream behind it.
func (h *ShadowTLSInbound) rebuild() error {
	if err := h.rebuildInner(); err != nil {
		return err
	}
	return h.rebuildService()
}

// rebuildInner republishes the per-user inner PSKs.
//
// Slot numbers are reassigned on every change, unlike ShadowsocksInbound which
// keeps them stable. Nothing depends on them here: the inner layer only decides
// whether a stream decrypts, while the accounting identity comes from the
// ShadowTLS layer via the auth context. In-flight connections are unaffected —
// the PSK map is consulted once per handshake, and established sessions hold
// their own derived keys.
func (h *ShadowTLSInbound) rebuildInner() error {
	slots := make([]int, len(h.users))
	passwords := make([]string, len(h.users))
	for i, u := range h.users {
		slots[i] = i
		passwords[i] = u.InnerPassword
	}
	if err := h.inner.UpdateUsersWithPasswords(slots, passwords); err != nil {
		return E.Cause(err, "update inner shadowsocks users")
	}
	return nil
}

// rebuildService recreates shadowtls.Service with the current user list and
// atomically stores it. Caller must hold h.mu.
//
// v3 requires at least one user: shadowtls.NewService rejects an empty list.
// Nodes are created before their subscriptions are fetched, so the user list is
// empty at that point and again if every user is later removed. Store a nil
// service for that window instead of failing — NewConnection rejects incoming
// connections until AddUsers supplies a user and the service is built.
func (h *ShadowTLSInbound) rebuildService() error {
	if h.baseVersion == 3 && len(h.users) == 0 {
		h.service.Store(nil)
		return nil
	}
	outer := make([]shadowtls.User, len(h.users))
	for i, u := range h.users {
		outer[i] = shadowtls.User{Name: u.Name, Password: u.Password}
	}
	svc, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version: h.baseVersion,
		Users:   outer,
		Handshake:              h.baseHandshake,
		HandshakeForServerName: h.baseHSForSNI,
		StrictMode:             h.baseStrictMode,
		WildcardSNI:            h.baseWildcardSNI,
		Handler:                (*shadowtlsHandler)(h),
		Logger:                 h.logger,
	})
	if err != nil {
		return err
	}
	h.service.Store(svc)
	return nil
}

// ─── connection handling ─────────────────────────────────────────────────────

func (h *ShadowTLSInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	svc := h.service.Load()
	if svc == nil {
		h.logger.DebugContext(ctx, "connection rejected: no users")
		N.CloseOnHandshakeFailure(conn, onClose, E.New("no users"))
		return
	}
	err := svc.NewConnection(adapter.WithContext(log.ContextWithNewID(ctx), &metadata), conn, metadata.Source, metadata.Destination, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

// ─── inboundHandler — the target after ShadowTLS unwrap ──────────────────────

type shadowtlsHandler ShadowTLSInbound

// NewConnectionEx receives the stream once the ShadowTLS handshake is done. The
// destination argument is not the client's target — shadowtls.Service echoes
// back whatever it was handed — so it is discarded and the real destination is
// read from the inner shadowsocks header instead. Auth already happened at the
// ShadowTLS layer; the user name rides along in ctx.
func (h *shadowtlsHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := h.inner.NewConnection(ctx, conn, M.Metadata{Source: source})
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", source))
		}
	}
}

// ─── routing after the inner header is parsed ────────────────────────────────

func (h *ShadowTLSInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	return h.router.RouteConnection(ctx, conn, metadata)
}

func (h *ShadowTLSInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	ctx = log.ContextWithNewID(ctx)
	userName, _ := auth.UserFromContext[string](ctx)
	if userName != "" {
		metadata.User = userName
	}
	h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	return h.router.RoutePacketConnection(ctx, conn, metadata)
}

func (h *ShadowTLSInbound) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		h.logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	h.logger.ErrorContext(ctx, err)
}
