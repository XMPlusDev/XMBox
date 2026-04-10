package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"dario.cat/mergo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/include"

	"github.com/xmplusdev/xmbox/core/inbound"
	"github.com/xmplusdev/xmbox/service"
)

type loadResult struct {
	server     *box.Box
	ctx        context.Context
	dispatcher *Dispatcher
	logFactory boxLog.Factory
}

type Instance struct {
	mu         sync.Mutex
	server     *box.Box
	config     *Config
	ctx        context.Context
	dispatcher *Dispatcher
	logFactory boxLog.Factory
	Service    []service.ControllerInterface
}

func New(config *Config) *Instance {
	return &Instance{config: config}
}

func (i *Instance) load(config *Config) (*loadResult, error) {
	ctx := context.Background()
	ibReg := include.InboundRegistry()
	inbound.RegisterAll(ibReg)

	ctx = box.Context(
		ctx,
		ibReg,
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)

	opts := option.Options{}

	logConfig := getDefaultLogConfig()
	if config.LogConfig != nil {
		if err := mergo.Merge(logConfig, config.LogConfig, mergo.WithOverride); err != nil {
			log.Panic(err)
			return nil, fmt.Errorf("merge log config: %w", err)
		}
	}
	opts.Log = &option.LogOptions{
		Disabled:  logConfig.Disabled,
		Level:     logConfig.Level,
		Timestamp: true,
		Output:    logConfig.Output,
	}

	if config.NtpConfig != nil && config.NtpConfig.Enable {
		opts.NTP = &option.NTPOptions{
			Enabled:       true,
			WriteToSystem: true,
			ServerOptions: option.ServerOptions{
				Server:     config.NtpConfig.Server,
				ServerPort: config.NtpConfig.ServerPort,
			},
		}
	}

	if config.DnsConfig != "" {
		dnsBytes, err := os.ReadFile(config.DnsConfig)
		if err != nil {
			log.Panic(err)
			return nil, fmt.Errorf("read DNS file: %w", err)
		}
		var dnsOptions option.DNSOptions
		if err := json.Unmarshal(dnsBytes, &dnsOptions); err != nil {
			log.Panic(err)
			return nil, fmt.Errorf("unmarshal DNS config: %w", err)
		}
		opts.DNS = &dnsOptions
	}

	if config.RouteConfig != "" {
		routeBytes, err := os.ReadFile(config.RouteConfig)
		if err != nil {
			return nil, fmt.Errorf("read route file: %w", err)
		}
		var routeOptions option.RouteOptions
		if err := json.Unmarshal(routeBytes, &routeOptions); err != nil {
			log.Panic(err)
			return nil, fmt.Errorf("unmarshal route config: %w", err)
		}
		opts.Route = &routeOptions
	}

	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		log.Panic(err)
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}

	dispatcher := &Dispatcher{}
	b.Router().AppendTracker(dispatcher)

	return &loadResult{
		server:     b,
		ctx:        ctx,
		dispatcher: dispatcher,
		logFactory: b.LogFactory(),
	}, nil
}

func (i *Instance) Start() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if globalFactory == nil {
		return fmt.Errorf("no controller factory registered — call core.SetControllerFactory before Start()")
	}

	result, err := i.load(i.config)
	if err != nil {
		log.Panic(err)
		return fmt.Errorf("load config: %w", err)
	}

	for _, s := range i.Service {
		if err := s.Close(); err != nil {
			log.Panic(err)
			return fmt.Errorf("stop existing service: %w", err)
		}
	}
	i.Service = nil

	if i.server != nil {
		i.server.Close()
		i.server = nil
	}

	i.server = result.server
	i.ctx = result.ctx
	i.dispatcher = result.dispatcher
	i.logFactory = result.logFactory

	if err := i.server.Start(); err != nil {
		i.server = nil
		i.ctx = nil
		i.dispatcher = nil
		i.logFactory = nil
		log.Panic(err)
		return fmt.Errorf("start sing-box instance: %w", err)
	}

	for _, nodeConfig := range i.config.NodesConfig {
		svc := globalFactory(i, nodeConfig)
		i.Service = append(i.Service, svc)
	}

	for _, s := range i.Service {
		if err := s.Start(); err != nil {
			log.Panic(err)
			return fmt.Errorf("start service: %w", err)
		}
	}

	return nil
}

func (i *Instance) Stop() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, s := range i.Service {
		if err := s.Close(); err != nil {
			log.Panic(err)
			return fmt.Errorf("stop service: %w", err)
		}
	}
	i.Service = nil

	if i.server != nil {
		i.server.Close()
		i.server = nil
		log.Println("XMBox successfully stopped")
	}

	return nil
}

func (i *Instance) GetBox() *box.Box             { return i.server }
func (i *Instance) GetCtx() context.Context      { return i.ctx }
func (i *Instance) GetLogFactory() boxLog.Factory { return i.logFactory }
func (i *Instance) GetDispatcher() *Dispatcher   { return i.dispatcher }

func (i *Instance) GetInbound(tag string) (adapter.Inbound, bool) {
	return i.server.Inbound().Get(tag)
}

func (i *Instance) DeleteCounter(tag string) {
    if i.dispatcher == nil {
        return
    }
    i.dispatcher.DeleteCounter(tag)
}

type ControllerFactory func(instance *Instance, nodeConfig *NodesConfig) service.ControllerInterface

var globalFactory ControllerFactory

func SetControllerFactory(f ControllerFactory) {
	globalFactory = f
}