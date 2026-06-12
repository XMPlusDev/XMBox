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
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// compile-time interface checks
var (
	_ adapter.TCPInjectableInbound = (*VLESSInbound)(nil)
)

// VLESSInbound is a full sing-box VLESS inbound with zero-downtime user
// management via AddUsers / DelUsers.
//
// Connection-safety guarantee: existing connections are NEVER closed when users
// are removed.  Authentication (UUID lookup in service.userMap) happens exactly
// once per TCP connection inside Service.NewConnection.  After that point the
// authenticated slot index is stored in ctx; the router goroutine runs entirely
// independently of the user table.  Calling DelUsers zeroes the slot and calls
// service.UpdateUsers — new connections from that UUID are rejected, but
// in-flight connections are not touched.
type VLESSInbound struct {
	inbound.Adapter
	ctx       context.Context
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	transport adapter.V2RayServerTransport
	service   *vless.Service[int]

	// user state — grows monotonically, slots are never reused
	mu       sync.Mutex
	users    []option.VLESSUser // indexed by slot; zero-value = deleted slot
	slotMap  map[string]int     // Name → slot (for upsert / delete)
	nameSnap atomic.Pointer[[]string]
}

// RegisterVLESS overrides the built-in VLESS factory in registry.
func RegisterVLESS(registry *inbound.Registry) {
	inbound.Register[option.VLESSInboundOptions](registry, C.TypeVLESS, newVLESSInbound)
}

func newVLESSInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.VLESSInboundOptions,
) (adapter.Inbound, error) {
	h := &VLESSInbound{
		Adapter: inbound.NewAdapter(C.TypeVLESS, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		slotMap: make(map[string]int),
	}

	var err error
	h.router, err = mux.NewRouterWithOptions(h.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}

	// Build VLESS service.
	service := vless.NewService[int](logger,
		adapter.NewUpstreamContextHandler(h.newConnectionEx, h.newPacketConnectionEx))
	h.service = service

	// Load initial users.
	h.mu.Lock()
	for _, u := range options.Users {
		slot := len(h.users)
		h.users = append(h.users, u)
		h.slotMap[u.Name] = slot
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()

	if options.TLS != nil {
		h.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				common.All(options.Users, func(it option.VLESSUser) bool { return it.Flow == "" }),
		})
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		h.transport, err = v2ray.NewServerTransport(ctx, logger,
			common.PtrValueOrDefault(options.Transport), h.tlsConfig,
			(*vlessTransportHandler)(h))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
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

// ─── lifecycle ────────────────────────────────────────────────────────────────

func (h *VLESSInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
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

func (h *VLESSInbound) Close() error {
	return common.Close(h.service, h.listener, h.tlsConfig, h.transport)
}

// ─── hot user management ─────────────────────────────────────────────────────

// AddUsers upserts VLESS users by Name. Existing slots are updated in-place;
// new names get a fresh slot. Thread-safe, no restart required.
func (h *VLESSInbound) AddUsers(users []option.VLESSUser) error {
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

// DelUsers removes users by Name. Deleted slots are zeroed but never reused,
// so in-flight authenticated connections can never be remapped to another user.
func (h *VLESSInbound) DelUsers(names []string) error {
	h.mu.Lock()
	for _, name := range names {
		if slot, ok := h.slotMap[name]; ok {
			h.users[slot] = option.VLESSUser{} // zero = deleted
			delete(h.slotMap, name)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()
	return nil
}

// rebuildSnapLocked refreshes the atomic name snapshot. Must hold h.mu.
func (h *VLESSInbound) rebuildSnapLocked() {
	snap := make([]string, len(h.users))
	for i, u := range h.users {
		snap[i] = u.Name
	}
	h.nameSnap.Store(&snap)
}

// syncService pushes the current active user set into the VLESS service.
func (h *VLESSInbound) syncService() {
	h.mu.Lock()
	var indices []int
	var uuids []string
	var flows []string
	for slot, u := range h.users {
		if u.UUID != "" { // non-empty UUID = active slot
			indices = append(indices, slot)
			uuids = append(uuids, u.UUID)
			flows = append(flows, u.Flow)
		}
	}
	h.mu.Unlock()
	h.service.UpdateUsers(indices, uuids, flows)
}

// ─── connection handling ─────────────────────────────────────────────────────

func (h *VLESSInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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

func (h *VLESSInbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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

func (h *VLESSInbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		h.logger.InfoContext(ctx, "[", F.ToString(user), "] inbound packet addr connection")
	} else {
		h.logger.InfoContext(ctx, "[", F.ToString(user), "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// userName returns the name for a slot index from the atomic snapshot.
func (h *VLESSInbound) userName(index int) string {
	snap := h.nameSnap.Load()
	if snap == nil || index >= len(*snap) {
		return F.ToString(index)
	}
	if name := (*snap)[index]; name != "" {
		return name
	}
	return F.ToString(index)
}

// ─── V2Ray transport shim ─────────────────────────────────────────────────────

var _ adapter.V2RayServerTransportHandler = (*vlessTransportHandler)(nil)

type vlessTransportHandler VLESSInbound

func (h *vlessTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*VLESSInbound)(h).NewConnection(ctx, conn, metadata, onClose)
}
