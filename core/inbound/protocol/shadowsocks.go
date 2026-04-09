package protocol

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ adapter.TCPInjectableInbound = (*ShadowsocksInbound)(nil)

// ShadowsocksInbound is a sing-box Shadowsocks multi-user inbound with
// zero-downtime hot user management via AddUsers / DelUsers.
//
// Authentication happens once per connection inside the service cipher layer.
// After that the user slot index is stored in ctx; the router goroutine runs
// entirely independently of the user table.  Calling DelUsers zeroes the slot
// and calls service.UpdateUsersWithPasswords — new connections from that user
// are rejected, but in-flight connections are not touched.
type ShadowsocksInbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  shadowsocks.MultiService[int]

	// user state — grows monotonically, slots are never reused
	mu       sync.Mutex
	users    []option.ShadowsocksUser // indexed by slot; zero-value = deleted slot
	slotMap  map[string]int           // Name → slot (for upsert / delete)
	nameSnap atomic.Pointer[[]string]
}

// RegisterShadowsocks overrides the built-in Shadowsocks factory in registry.
func RegisterShadowsocks(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocks, newShadowsocksInbound)
}

func newShadowsocksInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.ShadowsocksInboundOptions,
) (adapter.Inbound, error) {
	h := &ShadowsocksInbound{
		Adapter: inbound.NewAdapter(C.TypeShadowsocks, tag),
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

	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}

	upstreamHandler := adapter.NewUpstreamHandler(
		adapter.InboundContext{},
		h.newConnection,
		h.newPacketConnection,
		h,
	)
	var service shadowsocks.MultiService[int]
	if common.Contains(shadowaead_2022.List, options.Method) {
		service, err = shadowaead_2022.NewMultiServiceWithPassword[int](
			options.Method,
			options.Password,
			int64(udpTimeout.Seconds()),
			upstreamHandler,
			ntp.TimeFuncFromContext(ctx),
		)
	} else if common.Contains(shadowaead.List, options.Method) {
		service, err = shadowaead.NewMultiService[int](
			options.Method,
			int64(udpTimeout.Seconds()),
			upstreamHandler,
		)
	} else {
		return nil, E.New("unsupported method: " + options.Method)
	}
	if err != nil {
		return nil, err
	}
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
	if err = h.syncService(); err != nil {
		return nil, err
	}

	h.listener = listener.New(listener.Options{
		Context:                  ctx,
		Logger:                   logger,
		Network:                  options.Network.Build(),
		Listen:                   options.ListenOptions,
		ConnectionHandler:        h,
		PacketHandler:            h,
		ThreadUnsafePacketWriter: true,
	})
	return h, nil
}

// ─── lifecycle ────────────────────────────────────────────────────────────────

func (h *ShadowsocksInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *ShadowsocksInbound) Close() error {
	return h.listener.Close()
}

// ─── hot user management ─────────────────────────────────────────────────────

// AddUsers upserts Shadowsocks users by Name. Existing slots are updated
// in-place; new names get a fresh slot. Thread-safe, no restart required.
func (h *ShadowsocksInbound) AddUsers(users []option.ShadowsocksUser) error {
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

// DelUsers removes users by Name. Deleted slots are zeroed but never reused,
// so in-flight authenticated connections can never be remapped to another user.
func (h *ShadowsocksInbound) DelUsers(names []string) error {
	h.mu.Lock()
	for _, name := range names {
		if slot, ok := h.slotMap[name]; ok {
			h.users[slot] = option.ShadowsocksUser{} // zero = deleted
			delete(h.slotMap, name)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	return h.syncService()
}

// rebuildSnapLocked refreshes the atomic name snapshot. Must hold h.mu.
func (h *ShadowsocksInbound) rebuildSnapLocked() {
	snap := make([]string, len(h.users))
	for i, u := range h.users {
		snap[i] = u.Name
	}
	h.nameSnap.Store(&snap)
}

// syncService pushes the current active user set into the Shadowsocks service.
func (h *ShadowsocksInbound) syncService() error {
	h.mu.Lock()
	var indices []int
	var passwords []string
	for slot, u := range h.users {
		if u.Password != "" { // non-empty password = active slot
			indices = append(indices, slot)
			passwords = append(passwords, u.Password)
		}
	}
	h.mu.Unlock()
	return h.service.UpdateUsersWithPasswords(indices, passwords)
}

// ─── connection handling ─────────────────────────────────────────────────────

//nolint:staticcheck
func (h *ShadowsocksInbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.service.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

//nolint:staticcheck
func (h *ShadowsocksInbound) NewPacketEx(buffer *buf.Buffer, source M.Socksaddr) {
	err := h.service.NewPacket(h.ctx, &ssStubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		h.logger.Error(E.Cause(err, "process packet from ", source))
	}
}

func (h *ShadowsocksInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user := h.userName(userIndex)
	if user != "" {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	return h.router.RouteConnection(ctx, conn, metadata)
}

func (h *ShadowsocksInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user := h.userName(userIndex)
	if user != "" {
		metadata.User = user
	}
	ctx = log.ContextWithNewID(ctx)
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	return h.router.RoutePacketConnection(ctx, conn, metadata)
}

// userName returns the name for a slot index from the atomic snapshot.
func (h *ShadowsocksInbound) userName(index int) string {
	snap := h.nameSnap.Load()
	if snap == nil || index >= len(*snap) {
		return F.ToString(index)
	}
	if name := (*snap)[index]; name != "" {
		return name
	}
	return F.ToString(index)
}

func (h *ShadowsocksInbound) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		h.logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	h.logger.ErrorContext(ctx, err)
}

// ─── ssStubPacketConn ────────────────────────────────────────────────────────
// Required by NewPacketEx: the service needs a PacketConn for writing replies,
// but never calls Read on it (packets arrive via NewPacket, not Read).

var _ N.PacketConn = (*ssStubPacketConn)(nil)

type ssStubPacketConn struct{ N.PacketWriter }

func (c *ssStubPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { panic("stub") }
func (c *ssStubPacketConn) Close() error                                { return nil }
func (c *ssStubPacketConn) LocalAddr() net.Addr                         { panic("stub") }
func (c *ssStubPacketConn) SetDeadline(time.Time) error                 { panic("stub") }
func (c *ssStubPacketConn) SetReadDeadline(time.Time) error             { panic("stub") }
func (c *ssStubPacketConn) SetWriteDeadline(time.Time) error            { panic("stub") }
