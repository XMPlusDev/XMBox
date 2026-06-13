package instance

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
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/dispatcher"
	"github.com/xmplusdev/xmbox/inbound"
	"github.com/xmplusdev/xmbox/limiter"
	"github.com/xmplusdev/xmbox/scheduler"
	"github.com/xmplusdev/xmbox/service"
)

type loadResult struct {
	server     *box.Box
	ctx        context.Context
	dispatcher *dispatcher.Dispatcher
	logFactory boxLog.Factory
}

// Instance manages the sing-box engine and all node controllers.
type Instance struct {
	mu         sync.Mutex
	server     *box.Box
	instanceConfig     *Config
	ctx        context.Context
	dispatcher *dispatcher.Dispatcher
	logFactory boxLog.Factory
	Service    []service.ControllerInterface

	reverbCancels  []context.CancelFunc
	controllerMap  map[int]service.TriggerInterface
	reverbOutbound chan reverbOutbound     // outbound push to panel
	currentPusher  func(string, any) error // set when Reverb is connected

	// Server-mode fields (populated when ApiConfig.ServerID > 0)
	serverPoller      *scheduler.PeriodicTask
	serverPollTrigger chan struct{}
	serverStatusTask  *scheduler.PeriodicTask
}

// New returns an uninitialised Instance.
func New(instanceConfig *Config) *Instance {
	return &Instance{instanceConfig: instanceConfig}
}

// load creates and starts the sing-box engine from config.
func (i *Instance) load(instanceConfig *Config) (*loadResult, error) {
	ic := instanceConfig.InstanceConfig
	if ic == nil {
		ic = &InstanceConfig{}
	}
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
	if ic.LogConfig != nil {
		if err := mergo.Merge(logConfig, ic.LogConfig, mergo.WithOverride); err != nil {
			return nil, fmt.Errorf("merge log config: %w", err)
		}
	}
	opts.Log = &option.LogOptions{
		Disabled:  logConfig.Disabled,
		Level:     logConfig.Level,
		Timestamp: true,
		Output:    logConfig.Output,
	}

	if ic.NtpConfig != nil && ic.NtpConfig.Enable {
		opts.NTP = &option.NTPOptions{
			Enabled:       true,
			WriteToSystem: true,
			ServerOptions: option.ServerOptions{
				Server:     ic.NtpConfig.Server,
				ServerPort: ic.NtpConfig.ServerPort,
			},
		}
	}

	if ic.DNSConfig != nil && ic.DNSConfig.Enable && ic.DNSConfig.Path != "" {
		b, err := os.ReadFile(ic.DNSConfig.Path)
		if err != nil {
			return nil, fmt.Errorf("read DNS file: %w", err)
		}
		var dnsOpts option.DNSOptions
		if err := json.Unmarshal(b, &dnsOpts); err != nil {
			return nil, fmt.Errorf("parse DNS config: %w", err)
		}
		opts.DNS = &dnsOpts
	}

	if ic.RouteConfig != nil && ic.RouteConfig.Enable && ic.RouteConfig.Path != "" {
		b, err := os.ReadFile(ic.RouteConfig.Path)
		if err != nil {
			return nil, fmt.Errorf("read route file: %w", err)
		}
		var routeOpts option.RouteOptions
		if err := json.Unmarshal(b, &routeOpts); err != nil {
			return nil, fmt.Errorf("parse route config: %w", err)
		}
		opts.Route = &routeOpts
	}

	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}

	d := &dispatcher.Dispatcher{}
	b.Router().AppendTracker(d)

	return &loadResult{
		server:     b,
		ctx:        ctx,
		dispatcher: d,
		logFactory: b.LogFactory(),
	}, nil
}

// Start initialises the sing-box engine and launches all node controllers.
func (i *Instance) Start() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if globalFactory == nil {
		return fmt.Errorf("no controller factory registered — call SetControllerFactory before Start()")
	}

	// Initialise the global Redis limiter once (from top-level config).
	if err := limiter.Init(i.instanceConfig.RedisConfig); err != nil {
		return fmt.Errorf("limiter init: %w", err)
	}

	result, err := i.load(i.instanceConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Stop existing services/engine
	for _, s := range i.Service {
		_ = s.Close()
	}
	i.Service = nil
	if i.server != nil {
		i.server.Close()
		i.server = nil
	}
	for _, cancel := range i.reverbCancels {
		cancel()
	}
	i.reverbCancels = nil
	i.controllerMap = make(map[int]service.TriggerInterface)
	i.reverbOutbound = make(chan reverbOutbound, 64)

	i.server = result.server
	i.ctx = result.ctx
	i.dispatcher = result.dispatcher
	i.logFactory = result.logFactory

	if err := i.server.Start(); err != nil {
		i.server = nil
		return fmt.Errorf("start sing-box: %w", err)
	}
	log.Println("XMBox: sing-box engine started")

	// ----------------------------------------------------------------
	// Server mode: ApiConfig.ServerID > 0 — fetch own node list
	// ----------------------------------------------------------------
	if i.instanceConfig.ApiConfig == nil || i.instanceConfig.ApiConfig.ServerID == 0 {
		return fmt.Errorf("ApiConfig.ServerID is required — XMBox only supports server mode")
	}
	rootClient := api.New(i.instanceConfig.ApiConfig)
	if err := i.startServerMode(rootClient); err != nil {
		return fmt.Errorf("server mode start: %w", err)
	}

	// Start Reverb WebSocket listeners
	for _, cfg := range i.instanceConfig.ReverbConfig {
		if cfg == nil || !cfg.Enable {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		i.reverbCancels = append(i.reverbCancels, cancel)
		go i.reverbListener(ctx, cfg)
	}

	// Drain Reverb outbound push channel
	go i.drainReverbOutbound()

	return nil
}

// startServerMode fetches the node list, starts controllers, and launches the pollers.
func (i *Instance) startServerMode(rootClient api.API) error {
	resp, err := rootClient.GetServerNodes()
	if err != nil {
		return fmt.Errorf("GetServerNodes: %w", err)
	}
	
	if resp.Version < 2606120 {
		return fmt.Errorf("Backend does not support panel api version before v2606120. Update your panel.  Your panel api version is: %d", resp.Version)
	}

	for _, n := range resp.Nodes {
		nodeClient := api.New(i.instanceConfig.ApiConfig).ForNode(n.NodeID)
		nc := &NodesConfig{
			ApiConfig:  &api.Config{APIHost: i.instanceConfig.ApiConfig.APIHost, NodeID: n.NodeID, APIKey: i.instanceConfig.ApiConfig.APIKey, Timeout: i.instanceConfig.ApiConfig.Timeout},
			CertConfig: i.instanceConfig.CertConfig,
		}
		svc := globalFactory(i, nc)
		i.Service = append(i.Service, svc)
		if err := svc.Start(); err != nil {
			log.Printf("[ServerMode] failed to start node %d: %v", n.NodeID, err)
			continue
		}
		if t, ok := svc.(service.TriggerInterface); ok {
			i.controllerMap[t.GetNodeID()] = t
		}
		_ = nodeClient // ForNode used above; ref kept to avoid unused import warning
	}

	i.serverPollTrigger = make(chan struct{}, 1)
	i.startServerNodePoller(rootClient, resp.PollInterval)
	i.startServerStatusTask(rootClient)
	return nil
}

// Stop shuts down all services and the sing-box engine.
func (i *Instance) Stop() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.serverPoller != nil {
		i.serverPoller.Close()
	}
	if i.serverStatusTask != nil {
		i.serverStatusTask.Close()
	}

	for _, cancel := range i.reverbCancels {
		cancel()
	}
	i.reverbCancels = nil

	for _, s := range i.Service {
		if err := s.Close(); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	i.Service = nil
	i.controllerMap = nil

	if i.server != nil {
		i.server.Close()
		i.server = nil
		log.Println("XMBox: stopped")
	}
	return nil
}

// Getters used by controllers and managers
func (i *Instance) GetInstanceConfig() *InstanceConfig {
	if i.instanceConfig == nil {
		return &InstanceConfig{}
	}
	if i.instanceConfig.InstanceConfig == nil {
		return &InstanceConfig{}
	}
	return i.instanceConfig.InstanceConfig
}

func (i *Instance) GetBox() *box.Box                    { return i.server }
func (i *Instance) GetCtx() context.Context             { return i.ctx }
func (i *Instance) GetLogFactory() boxLog.Factory       { return i.logFactory }
func (i *Instance) GetDispatcher() *dispatcher.Dispatcher { return i.dispatcher }

func (i *Instance) GetInbound(tag string) (adapter.Inbound, bool) {
	return i.server.Inbound().Get(tag)
}

func (i *Instance) DeleteCounter(tag string) {
	if i.dispatcher != nil {
		i.dispatcher.DeleteCounter(tag)
	}
}

// ControllerFactory is the constructor type for node controllers.
type ControllerFactory func(instance *Instance, nodeConfig *NodesConfig) service.ControllerInterface

var globalFactory ControllerFactory

// SetControllerFactory registers the factory used to create node controllers.
func SetControllerFactory(f ControllerFactory) { globalFactory = f }
