package protocol

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.TCPInjectableInbound = (*TrojanInbound)(nil)

// TrojanInbound is a full sing-box Trojan inbound with zero-downtime user management.
type TrojanInbound struct {
	inbound.Adapter
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	listener                 *listener.Listener
	tlsConfig                tls.ServerConfig
	transport                adapter.V2RayServerTransport
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
	service                  *trojan.Service[int]

	mu       sync.Mutex
	users    []option.TrojanUser
	slotMap  map[string]int
	nameSnap atomic.Pointer[[]string]
}

// RegisterTrojan overrides the built-in Trojan factory in registry.
func RegisterTrojan(registry *inbound.Registry) {
	inbound.Register[option.TrojanInboundOptions](registry, C.TypeTrojan, newTrojanInbound)
}

func newTrojanInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.TrojanInboundOptions,
) (adapter.Inbound, error) {
	h := &TrojanInbound{
		Adapter: inbound.NewAdapter(C.TypeTrojan, tag),
		router:  router,
		logger:  logger,
		slotMap: make(map[string]int),
	}

	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}

	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			h.fallbackAddr = options.Fallback.Build()
			if !h.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", h.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if h.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			alpnMap := make(map[string]M.Socksaddr)
			for proto, dest := range options.FallbackForALPN {
				addr := dest.Build()
				if !addr.IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", proto, ": ", addr)
				}
				alpnMap[proto] = addr
			}
			h.fallbackAddrTLSNextProto = alpnMap
		}
		fallbackHandler = adapter.NewUpstreamContextHandlerEx(h.fallbackConnection, nil)
	}

	service := trojan.NewService[int](
		adapter.NewUpstreamContextHandlerEx(h.newConnection, h.newPacketConnection),
		fallbackHandler,
		logger)
	if err := service.UpdateUsers(
		common.MapIndexed(options.Users, func(i int, _ option.TrojanUser) int { return i }),
		common.Map(options.Users, func(u option.TrojanUser) string { return u.Password }),
	); err != nil {
		return nil, err
	}

	h.mu.Lock()
	for _, u := range options.Users {
		slot := len(h.users)
		h.users = append(h.users, u)
		h.slotMap[u.Name] = slot
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.service = service

	var err error
	if options.Transport != nil {
		h.transport, err = v2ray.NewServerTransport(ctx, logger,
			common.PtrValueOrDefault(options.Transport), h.tlsConfig,
			(*trojanTransportHandler)(h))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	h.router, err = mux.NewRouterWithOptions(h.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
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

func (h *TrojanInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			if sErr := h.transport.Serve(tcpListener); sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			if sErr := h.transport.ServePacket(udpConn); sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

func (h *TrojanInbound) Close() error {
	return common.Close(h.listener, h.tlsConfig, h.transport)
}

// ─── hot user management ─────────────────────────────────────────────────────

func (h *TrojanInbound) AddUsers(users []option.TrojanUser) error {
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
	return h.syncService()
}

func (h *TrojanInbound) DelUsers(names []string) error {
	h.mu.Lock()
	for _, name := range names {
		if slot, ok := h.slotMap[name]; ok {
			h.users[slot] = option.TrojanUser{}
			delete(h.slotMap, name)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	return h.syncService()
}

func (h *TrojanInbound) rebuildSnapLocked() {
	snap := make([]string, len(h.users))
	for i, u := range h.users {
		snap[i] = u.Name
	}
	h.nameSnap.Store(&snap)
}

func (h *TrojanInbound) syncService() error {
	h.mu.Lock()
	var indices []int
	var passwords []string
	for slot, u := range h.users {
		if u.Password != "" {
			indices = append(indices, slot)
			passwords = append(passwords, u.Password)
		}
	}
	h.mu.Unlock()
	return h.service.UpdateUsers(indices, passwords)
}

// ─── connection handling ─────────────────────────────────────────────────────

func (h *TrojanInbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *TrojanInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.userName(userIndex)
	if user != "" {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", F.ToString(user), "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *TrojanInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.userName(userIndex)
	if user != "" {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", F.ToString(user), "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *TrojanInbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			cs := tlsConn.ConnectionState()
			if cs.NegotiatedProtocol != "" {
				var ok bool
				if fallbackAddr, ok = h.fallbackAddrTLSNextProto[cs.NegotiatedProtocol]; !ok {
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *TrojanInbound) userName(index int) string {
	snap := h.nameSnap.Load()
	if snap == nil || index >= len(*snap) {
		return F.ToString(index)
	}
	if name := (*snap)[index]; name != "" {
		return name
	}
	return F.ToString(index)
}

var _ adapter.V2RayServerTransportHandler = (*trojanTransportHandler)(nil)

type trojanTransportHandler TrojanInbound

func (h *trojanTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*TrojanInbound)(h).NewConnectionEx(ctx, conn, metadata, onClose)
}
