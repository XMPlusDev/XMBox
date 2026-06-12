package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// NaiveConfigureHTTP3ListenerFunc is set by the naivequic init package
// (built with the with_quic tag) to wire up HTTP/3 + QUIC support.
var NaiveConfigureHTTP3ListenerFunc func(
	ctx context.Context,
	logger logger.Logger,
	listener *listener.Listener,
	handler http.Handler,
	tlsConfig tls.ServerConfig,
	options option.NaiveInboundOptions,
) (io.Closer, error)

// NaiveWrapError is set by the naivequic init package to wrap QUIC errors.
var NaiveWrapError func(error) error

func RegisterNaive(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, newNaiveInbound)
}

type NaiveInbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	options          option.NaiveInboundOptions
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
	h3Server         io.Closer

	mu       sync.Mutex
	users    []auth.User
	authSnap atomic.Pointer[auth.Authenticator]
}

func newNaiveInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.NaiveInboundOptions,
) (adapter.Inbound, error) {
	h := &NaiveInbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
		users:            options.Users,
	}
	if common.Contains(h.network, N.NetworkUDP) {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("TLS is required for QUIC server")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}
	h.authSnap.Store(auth.NewAuthenticator(options.Users))
	return h, nil
}

// ─── lifecycle ────────────────────────────────────────────────────────────────

func (h *NaiveInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if common.Contains(h.network, N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		h.httpServer = &http.Server{
			Handler: h2c.NewHandler(h, &http2.Server{}),
			BaseContext: func(net.Listener) context.Context {
				return h.ctx
			},
		}
		go func() {
			ln := net.Listener(tcpListener)
			if h.tlsConfig != nil {
				protos := h.tlsConfig.NextProtos()
				if len(protos) == 0 {
					h.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
				} else if !common.Contains(protos, http2.NextProtoTLS) {
					h.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, protos...))
				}
				ln = aTLS.NewListener(tcpListener, h.tlsConfig)
			}
			sErr := h.httpServer.Serve(ln)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				h.logger.Error("http server serve error: ", sErr)
			}
		}()
	}

	if common.Contains(h.network, N.NetworkUDP) {
		if NaiveConfigureHTTP3ListenerFunc != nil {
			h3Server, err := NaiveConfigureHTTP3ListenerFunc(h.ctx, h.logger, h.listener, h, h.tlsConfig, h.options)
			if err == nil {
				h.h3Server = h3Server
			} else if len(h.network) > 1 {
				h.logger.Warn(E.Cause(err, "naive http3 disabled"))
			} else {
				return err
			}
		}
	}

	return nil
}

func (h *NaiveInbound) Close() error {
	return common.Close(&h.listener, common.PtrOrNil(h.httpServer), h.h3Server, h.tlsConfig)
}

// ─── hot user management ─────────────────────────────────────────────────────

func (h *NaiveInbound) AddUsers(users []auth.User) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := make(map[string]int, len(h.users))
	for i, u := range h.users {
		idx[u.Username] = i
	}
	for _, u := range users {
		if i, ok := idx[u.Username]; ok {
			h.users[i] = u
		} else {
			h.users = append(h.users, u)
		}
	}
	h.authSnap.Store(auth.NewAuthenticator(h.users))
	return nil
}

func (h *NaiveInbound) DelUsers(names []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	del := make(map[string]struct{}, len(names))
	for _, n := range names {
		del[n] = struct{}{}
	}
	remaining := h.users[:0]
	for _, u := range h.users {
		if _, ok := del[u.Username]; !ok {
			remaining = append(remaining, u)
		}
	}
	h.users = remaining
	h.authSnap.Store(auth.NewAuthenticator(h.users))
	return nil
}

// ─── HTTP handler ─────────────────────────────────────────────────────────────

func (h *NaiveInbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	if request.Method != "CONNECT" {
		naiveRejectHTTP(writer, http.StatusBadRequest)
		h.logBadRequest(ctx, request, E.New("not CONNECT request"))
		return
	}
	if request.Header.Get("Padding") == "" {
		naiveRejectHTTP(writer, http.StatusBadRequest)
		h.logBadRequest(ctx, request, E.New("missing naive padding"))
		return
	}
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = h.authSnap.Load().Verify(userName, password)
	}
	if !authOk {
		naiveRejectHTTP(writer, http.StatusProxyAuthRequired)
		h.logBadRequest(ctx, request, E.New("authorization failed"))
		return
	}
	writer.Header().Set("Padding", generatePaddingHeader())
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()

	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	source := sHttp.SourceAddress(request)
	destination := M.ParseSocksaddr(hostPort).Unwrap()

	if hijacker, ok := writer.(http.Hijacker); ok {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			h.logBadRequest(ctx, request, E.New("hijack failed"))
			return
		}
		h.serveNaiveConn(ctx, false, &naiveConn{Conn: conn}, userName, source, destination)
	} else {
		h.serveNaiveConn(ctx, true, &naiveH2Conn{
			reader:        request.Body,
			writer:        writer,
			flusher:       writer.(http.Flusher),
			remoteAddress: source,
		}, userName, source, destination)
	}
}

func (h *NaiveInbound) serveNaiveConn(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if userName != "" {
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection from ", source)
		h.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		h.router.RouteConnectionEx(ctx, conn, metadata, nil)
	} else {
		done := make(chan struct{})
		wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
		h.router.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) {
			close(done)
		}))
		<-done
		wrapper.CloseWrapper()
	}
}

func (h *NaiveInbound) logBadRequest(ctx context.Context, request *http.Request, err error) {
	h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func naiveRejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)
		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
