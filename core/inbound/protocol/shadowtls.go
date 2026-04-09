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
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

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
	router   adapter.Router
	logger   logger.ContextLogger
	listener *listener.Listener

	// service is swapped atomically on user changes
	service atomic.Pointer[shadowtls.Service]

	// base config — everything except Users; used to recreate the service
	mu              sync.Mutex
	users           []shadowtls.User
	baseVersion     int
	basePassword    string // v1/v2 single shared password
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
		router:  router,
		logger:  logger,
	}

	if options.Version == 0 {
		options.Version = 1
	}
	h.baseVersion = options.Version
	h.basePassword = options.Password
	h.baseStrictMode = options.StrictMode
	h.baseWildcardSNI = shadowtls.WildcardSNI(options.WildcardSNI)

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

	// Initial users (v3 only; v1/v2 use a single shared password).
	h.users = common.Map(options.Users, func(it option.ShadowTLSUser) shadowtls.User {
		return (shadowtls.User)(it)
	})

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

// AddUsers upserts ShadowTLS users by Name (v3 only; recreates service atomically).
func (h *ShadowTLSInbound) AddUsers(users []option.ShadowTLSUser) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := make(map[string]int, len(h.users))
	for i, u := range h.users {
		idx[u.Name] = i
	}
	for _, u := range users {
		su := (shadowtls.User)(u)
		if i, ok := idx[su.Name]; ok {
			h.users[i] = su
		} else {
			idx[su.Name] = len(h.users)
			h.users = append(h.users, su)
		}
	}
	return h.rebuildService()
}

// DelUsers removes ShadowTLS users by Name (v3 only; recreates service atomically).
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
	return h.rebuildService()
}

// rebuildService recreates shadowtls.Service with the current user list and
// atomically stores it. Caller must hold h.mu.
func (h *ShadowTLSInbound) rebuildService() error {
	svc, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version:                h.baseVersion,
		Password:               h.basePassword,
		Users:                  h.users,
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

func (h *ShadowTLSInbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	svc := h.service.Load()
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

func (h *shadowtlsHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
