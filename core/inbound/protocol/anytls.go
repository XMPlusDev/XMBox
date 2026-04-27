package protocol

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
)

type AnyTLSInbound struct {
	inbound.Adapter
	tlsConfig tls.ServerConfig
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener

	service *anytls.Service

	mu    sync.Mutex
	users []anytls.User
}

func RegisterAnyTLS(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, newAnyTLSInbound)
}

func newAnyTLSInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.AnyTLSInboundOptions,
) (adapter.Inbound, error) {
	h := &AnyTLSInbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	h.users = common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
		return (anytls.User)(it)
	})

	svc, err := anytls.NewService(anytls.ServiceConfig{
		Users:         h.users,
		PaddingScheme: paddingScheme,
		Handler:       (*anytlsHandler)(h),
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	h.service = svc

	h.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: h,
	})
	return h, nil
}

func (h *AnyTLSInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *AnyTLSInbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *AnyTLSInbound) AddUsers(users []option.AnyTLSUser) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := make(map[string]int, len(h.users))
	for i, u := range h.users {
		idx[u.Name] = i
	}
	for _, u := range users {
		au := (anytls.User)(u)
		if i, ok := idx[au.Name]; ok {
			h.users[i] = au 
		} else {
			idx[au.Name] = len(h.users)
			h.users = append(h.users, au)
		}
	}
	h.service.UpdateUsers(h.users)
	return nil
}

func (h *AnyTLSInbound) DelUsers(names []string) error {
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
	h.service.UpdateUsers(h.users)
	return nil
}

func (h *AnyTLSInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
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

type anytlsHandler AnyTLSInbound

func (h *anytlsHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
