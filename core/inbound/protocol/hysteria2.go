package protocol

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Hysteria2Inbound struct {
	inbound.Adapter
	router    adapter.Router
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	service   *hysteria2.Service[int]

	mu       sync.Mutex
	users    []option.Hysteria2User 
	slotMap  map[string]int         
	nameSnap atomic.Pointer[[]string]
}

func RegisterHysteria2(registry *inbound.Registry) {
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, newHysteria2Inbound)
}

func newHysteria2Inbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.Hysteria2InboundOptions,
) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}

	var masqueradeHandler http.Handler
	if options.Masquerade != nil && options.Masquerade.Type != "" {
		switch options.Masquerade.Type {
		case C.Hysterai2MasqueradeTypeFile:
			masqueradeHandler = http.FileServer(http.Dir(options.Masquerade.FileOptions.Directory))
		case C.Hysterai2MasqueradeTypeProxy:
			masqueradeURL, err := url.Parse(options.Masquerade.ProxyOptions.URL)
			if err != nil {
				return nil, E.Cause(err, "parse masquerade URL")
			}
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					if !options.Masquerade.ProxyOptions.RewriteHost {
						r.Out.Host = r.In.Host
					}
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
			}
		case C.Hysterai2MasqueradeTypeString:
			masqueradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if options.Masquerade.StringOptions.StatusCode != 0 {
					w.WriteHeader(options.Masquerade.StringOptions.StatusCode)
				}
				for key, values := range options.Masquerade.StringOptions.Headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.Write([]byte(options.Masquerade.StringOptions.Content)) //nolint:errcheck
			})
		default:
			return nil, E.New("unknown masquerade type: ", options.Masquerade.Type)
		}
	}

	h := &Hysteria2Inbound{
		Adapter: inbound.NewAdapter(C.TypeHysteria2, tag),
		router:  router,
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

	service, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:               ctx,
		Logger:                logger,
		BrutalDebug:           options.BrutalDebug,
		SendBPS:               uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:            uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             tlsConfig,
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            udpTimeout,
		Handler:               h,
		MasqueradeHandler:     masqueradeHandler,
		BBRProfile:            options.BBRProfile,
	})
	if err != nil {
		return nil, err
	}
	h.service = service

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

func (h *Hysteria2Inbound) Start(stage adapter.StartStage) error {
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
	return h.service.Start(packetConn)
}

func (h *Hysteria2Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig, common.PtrOrNil(h.service))
}

func (h *Hysteria2Inbound) AddUsers(users []option.Hysteria2User) error {
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

func (h *Hysteria2Inbound) DelUsers(names []string) error {
	h.mu.Lock()
	for _, name := range names {
		if slot, ok := h.slotMap[name]; ok {
			h.users[slot] = option.Hysteria2User{}
			delete(h.slotMap, name)
		}
	}
	h.rebuildSnapLocked()
	h.mu.Unlock()
	h.syncService()
	return nil
}

func (h *Hysteria2Inbound) rebuildSnapLocked() {
	snap := make([]string, len(h.users))
	for i, u := range h.users {
		snap[i] = u.Name
	}
	h.nameSnap.Store(&snap)
}

func (h *Hysteria2Inbound) syncService() {
	h.mu.Lock()
	var userList []int
	var passwordList []string
	for slot, u := range h.users {
		if u.Password != "" {
			userList = append(userList, slot)
			passwordList = append(passwordList, u.Password)
		}
	}
	h.mu.Unlock()
	h.service.UpdateUsers(userList, passwordList)
}

func (h *Hysteria2Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listener.ListenOptions().Detour
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

func (h *Hysteria2Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listener.ListenOptions().Detour
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

func (h *Hysteria2Inbound) userName(index int) string {
	snap := h.nameSnap.Load()
	if snap == nil || index >= len(*snap) {
		return ""
	}
	return (*snap)[index]
}
