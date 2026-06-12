package protocol

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	qtls "github.com/sagernet/sing-quic"

	"github.com/gofrs/uuid/v5"
)

// TUICInbound is a full sing-box TUIC inbound with zero-downtime user management.
type TUICInbound struct {
	inbound.Adapter
	router    adapter.ConnectionRouterEx
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	server    *tuic.Service[int]

	mu       sync.Mutex
	users    []option.TUICUser // slot-indexed; zero-value = deleted
	slotMap  map[string]int    // Name → slot
	nameSnap atomic.Pointer[[]string]
}

// RegisterTUIC overrides the built-in TUIC factory in registry.
func RegisterTUIC(registry *inbound.Registry) {
	inbound.Register[option.TUICInboundOptions](registry, C.TypeTUIC, newTUICInbound)
}

func newTUICInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.TUICInboundOptions,
) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	h := &TUICInbound{
		Adapter: inbound.NewAdapter(C.TypeTUIC, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		tlsConfig: tlsConfig,
		slotMap:   make(map[string]int),
	}

	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}

	service, err := tuic.NewService[int](tuic.ServiceOptions{
		Context:           ctx,
		Logger:            logger,
		TLSConfig:         tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		CongestionControl: options.CongestionControl,
		AuthTimeout:       time.Duration(options.AuthTimeout),
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
		UDPTimeout:        udpTimeout,
		Handler:           h,
	})
	if err != nil {
		return nil, err
	}
	h.server = service

	h.mu.Lock()
	for _, u := range options.Users {
		slot := len(h.users)
		h.users = append(h.users, u)
		h.slotMap[u.Name] = slot
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()

	return h, nil
}

func (h *TUICInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.server.Start(packetConn)
}

func (h *TUICInbound) Close() error {
	return common.Close(h.listener, h.tlsConfig, common.PtrOrNil(h.server))
}

// ─── hot user management ─────────────────────────────────────────────────────

func (h *TUICInbound) AddUsers(users []option.TUICUser) error {
	h.mu.Lock()
	for _, u := range users {
		if slot, ok := h.slotMap[u.Name]; ok {
			h.users[slot] = u
		} else {
			h.slotMap[u.Name] = len(h.users)
			h.users = append(h.users, u)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()
	return nil
}

func (h *TUICInbound) DelUsers(names []string) error {
	h.mu.Lock()
	for _, name := range names {
		if slot, ok := h.slotMap[name]; ok {
			h.users[slot] = option.TUICUser{}
			delete(h.slotMap, name)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()
	return nil
}

func (h *TUICInbound) rebuildSnapLocked() {
	snap := make([]string, len(h.users))
	for i, u := range h.users {
		snap[i] = u.Name
	}
	h.nameSnap.Store(&snap)
}

func (h *TUICInbound) syncService() {
	h.mu.Lock()
	var userList []int
	var uuidList [][16]byte
	var passwordList []string
	for slot, u := range h.users {
		if u.UUID == "" {
			continue // deleted slot
		}
		uid, err := uuid.FromString(u.UUID)
		if err != nil {
			continue
		}
		userList = append(userList, slot)
		uuidList = append(uuidList, uid)
		passwordList = append(passwordList, u.Password)
	}
	h.mu.Unlock()
	h.server.UpdateUsers(userList, uuidList, passwordList)
}

// ─── TUIC handler (N.TCPConnectionHandlerEx + N.UDPConnectionHandlerEx) ──────

func (h *TUICInbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	if userName := h.userName(userID); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *TUICInbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	if userName := h.userName(userID); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *TUICInbound) userName(index int) string {
	snap := h.nameSnap.Load()
	if snap == nil || index >= len(*snap) {
		return ""
	}
	return (*snap)[index]
}
