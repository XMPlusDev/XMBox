package controller

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/helper/cert"
	"github.com/xmplusdev/xmbox/core/instance"
	"github.com/xmplusdev/xmbox/limiter"
	"github.com/xmplusdev/xmbox/node"
	"github.com/xmplusdev/xmbox/helper/scheduler"
	"github.com/xmplusdev/xmbox/service"
	"github.com/xmplusdev/xmbox/subscription"
)

func init() {
	instance.SetControllerFactory(func(inst *instance.Instance, nodeConfig *instance.NodesConfig) service.ControllerInterface {
		apiClient := api.New(nodeConfig.ApiConfig)
		cfg := &node.Config{
			InstanceConfig: &node.InstanceConfig{},
		}
		if nodeConfig != nil {
			cfg.CertConfig = nodeConfig.CertConfig
		}
		if ic := inst.GetInstanceConfig(); ic != nil && ic.MultiplexConfig != nil {
			cfg.InstanceConfig.MultiplexConfig = ic.MultiplexConfig
		}
		return New(inst, apiClient, cfg)
	})
}

var _ service.ControllerInterface = (*Controller)(nil)

var safeCertName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// Controller manages one node: fetching config, managing subscriptions, reporting traffic.
type Controller struct {
	coreInstance *instance.Instance
	config       *node.Config
	clientInfo   api.ClientInfo
	client       api.API
	nodeInfo     *api.NodeInfo
	blockRules   []api.BlockRule
	Tag          string
	LogPrefix    string

	currentPollInterval time.Duration
	subscriptionList    *[]api.SubscriptionInfo

	relayNodeInfo *api.RelayNodeInfo
	RelayTag      string
	Relay         bool
	relayGen      int
	relaySubs     *[]api.SubscriptionInfo // subscriptions the current relay was built for

	taskManager *scheduler.Manager
	nodeManager *node.Manager
	subManager  *subscription.Manager

	nodeSyncTrigger         chan struct{}
	subscriptionSyncTrigger chan struct{}
	intervalChangeCh        chan time.Duration
	triggerCtx              context.Context
	triggerCancel           context.CancelFunc

	// pusher is the active Reverb push function from the parent instance.
	// It is optional; when set, traffic reports can be pushed over WebSocket.
	pusher func(string, any) error

	// mu serializes apiMonitor, ruleMonitor and Close, which run on different
	// goroutines and all change the router.
	mu           sync.Mutex
	closed       bool
	pendingRules []api.BlockRule
	hasPending   bool
}

// New constructs a Controller.  pusher may be nil.
func New(coreInstance *instance.Instance, apiClient api.API, config *node.Config) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		coreInstance:            coreInstance,
		config:                  config,
		client:                  apiClient,
		taskManager:             scheduler.NewManager(),
		nodeManager:             node.NewManager(coreInstance, apiClient),
		subManager:              subscription.NewManager(coreInstance, apiClient),
		nodeSyncTrigger:         make(chan struct{}, 1),
		subscriptionSyncTrigger: make(chan struct{}, 1),
		intervalChangeCh:        make(chan time.Duration, 1),
		triggerCtx:              ctx,
		triggerCancel:           cancel,
		pusher:                  coreInstance.PushEvent,
	}
}

// nodePusher wraps the instance-level pusher with this controller's node ID,
// matching the envelope format the panel expects from Reverb push events.
func (c *Controller) nodePusher() func(string, any) error {
	if c.pusher == nil {
		return nil
	}
	nodeID := c.clientInfo.NodeID
	push := c.pusher
	return func(event string, data any) error {
		return push(event, map[string]any{
			"node_id":   nodeID,
			"server_id": c.coreInstance.GetServerID(),
			"data":      data,
		})
	}
}

// --- service.TriggerInterface ---

func (c *Controller) TriggerNodeSync() {
	select {
	case c.nodeSyncTrigger <- struct{}{}:
	default:
	}
}

func (c *Controller) TriggerSubscriptionSync() {
	select {
	case c.subscriptionSyncTrigger <- struct{}{}:
	default:
	}
}

func (c *Controller) GetNodeID() int { return c.clientInfo.NodeID }

// --- service.ControllerInterface ---

func (c *Controller) Start() error {
	c.clientInfo = c.client.Describe()

	nodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("GetNodeInfo: %w", err)
	}
	c.nodeInfo = nodeInfo
	c.Tag = c.buildNodeTag()
	c.LogPrefix = c.logPrefix()

	blockRules, err := c.client.GetBlockRules()
	if err != nil {
		return fmt.Errorf("GetBlockRules: %w", err)
	}
	c.blockRules = blockRules
	log.Printf("%s loaded %d block rules", c.LogPrefix, len(blockRules))

	subscriptions, err := c.client.GetSubscriptionList()
	if err != nil {
		return fmt.Errorf("GetSubscriptionList: %w", err)
	}
	c.subscriptionList = subscriptions

	// The relay goes up before the inbound accepts connections.
	if err := c.syncRelay(c.nodeInfo, c.subscriptionList, true, true); err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	// AddNode puts the block rules in front of the relay rules.
	if err := c.nodeManager.AddNode(c.nodeInfo, c.Tag, c.config, c.nodePusher(), c.blockRules); err != nil {
		return fmt.Errorf("AddNode: %w", err)
	}

	if err := c.subManager.AddSubscriptions(subscriptions, nodeInfo, c.Tag); err != nil {
		return fmt.Errorf("AddSubscriptions: %w", err)
	}
	log.Printf("%s added %d subscriptions", c.LogPrefix, len(*subscriptions))

	if err := limiter.AddLimiter(
		c.Tag,
		nodeInfo.UpdateInterval,
		nodeInfo.SpeedLimit,
		nodeInfo.IgnoreIPs,
		subscriptions,
	); err != nil {
		log.Printf("%s AddLimiter error: %v", c.LogPrefix, err)
	}

	c.currentPollInterval = c.pollInterval()

	c.taskManager.Add(scheduler.NewWithDelay(c.LogPrefix, "node", c.currentPollInterval, c.apiMonitor))
	c.taskManager.Add(scheduler.NewWithDelay(c.LogPrefix, "subscriptions", c.currentPollInterval,
		func() error { return c.subManager.SubscriptionMonitor(c.Tag, c.LogPrefix, c.nodePusher()) }))
	c.taskManager.Add(scheduler.NewWithDelay(c.LogPrefix, "rules", c.currentPollInterval, c.ruleMonitor))

	c.addCertTasks()

	go c.webhookTriggerLoop(c.currentPollInterval)

	log.Printf("%s starting %d task schedulers", c.LogPrefix, c.taskManager.Count())
	return c.taskManager.StartAll()
}

func (c *Controller) Close() error {
	log.Printf("%s closing %d task schedulers", c.LogPrefix, c.taskManager.Count())
	c.triggerCancel()

	// A monitor that is waiting for the lock sees `closed` and does nothing.
	c.mu.Lock()
	c.closed = true
	if err := limiter.DeleteLimiter(c.Tag); err != nil {
		log.Printf("%s DeleteLimiter error: %v", c.LogPrefix, err)
	}
	if err := c.nodeManager.RemoveNode(c.Tag); err != nil {
		log.Printf("%s Close RemoveNode error: %v", c.LogPrefix, err)
	}
	c.teardownRelay()
	c.mu.Unlock()

	return c.taskManager.CloseAll()
}

// webhookTriggerLoop handles debounced Reverb triggers and periodic fallback ticks.
func (c *Controller) webhookTriggerLoop(fallbackInterval time.Duration) {
	const debounceDuration = 3 * time.Second

	ticker := time.NewTicker(fallbackInterval)
	defer ticker.Stop()

	var lastSync time.Time

	for {
		select {
		case <-c.triggerCtx.Done():
			return

		case newInterval := <-c.intervalChangeCh:
			ticker.Reset(newInterval)
			fallbackInterval = newInterval
			log.Printf("%s webhook interval updated to %v", c.LogPrefix, newInterval)

		case <-c.nodeSyncTrigger:
			if time.Since(lastSync) < debounceDuration {
				log.Printf("%s webhook node trigger debounced", c.LogPrefix)
				drainChan(c.nodeSyncTrigger)
				continue
			}
			log.Printf("%s webhook node trigger: syncing now", c.LogPrefix)
			if err := c.apiMonitor(); err != nil {
				log.Printf("%s webhook node sync error: %v", c.LogPrefix, err)
			}
			lastSync = time.Now()
			drainChan(c.nodeSyncTrigger)
			ticker.Reset(fallbackInterval)

		case <-c.subscriptionSyncTrigger:
			if time.Since(lastSync) < debounceDuration {
				log.Printf("%s webhook subscription trigger debounced", c.LogPrefix)
				drainChan(c.subscriptionSyncTrigger)
				continue
			}
			log.Printf("%s webhook subscription trigger: syncing now", c.LogPrefix)
			if err := c.apiMonitor(); err != nil {
				log.Printf("%s webhook subscription sync error: %v", c.LogPrefix, err)
			}
			lastSync = time.Now()
			drainChan(c.subscriptionSyncTrigger)
			ticker.Reset(fallbackInterval)

		case <-ticker.C:
			lastSync = time.Now()
		}
	}
}

func drainChan(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (c *Controller) pollInterval() time.Duration {
	return time.Duration(c.nodeInfo.UpdateInterval) * time.Second
}

// nodeInfoChangedStructurally reports whether old and new NodeInfo differ in
// a field that requires rebuilding the inbound (e.g. port, protocol, key,
// transport, or TLS settings). SpeedLimit, IgnoreIPs, and UpdateInterval can
// all be applied in-place via limiter.UpdateNodeInfo without dropping
// connections, so they're excluded from the comparison to avoid an
// unnecessary outage on every minor poll-cycle change.
func nodeInfoChangedStructurally(old, new *api.NodeInfo) bool {
	if old == nil || new == nil {
		return true
	}
	o, n := *old, *new
	o.SpeedLimit, n.SpeedLimit = 0, 0
	o.IgnoreIPs, n.IgnoreIPs = nil, nil
	o.UpdateInterval, n.UpdateInterval = 0, 0
	return !reflect.DeepEqual(o, n)
}

// apiMonitor fetches updated node info and subscription list, then reconciles
// the running state accordingly.
func (c *Controller) apiMonitor() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}

	nodeInfoChanged := true
	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			log.Printf("%s GetNodeInfo error: %v", c.LogPrefix, err)
			return nil
		}
	}

	subscriptionChanged := true
	newSubs, err := c.client.GetSubscriptionList()
	if err != nil {
		if err.Error() == api.SubscriptionNotModified {
			subscriptionChanged = false
			newSubs = c.subscriptionList
		} else {
			log.Printf("%s GetSubscriptionList error: %v", c.LogPrefix, err)
			return nil
		}
	}

	nodeInfoActuallyChanged := nodeInfoChanged && nodeInfoChangedStructurally(c.nodeInfo, newNodeInfo)

	// Set when the structural branch below already brought the relay up to date.
	relaySynced := false

	if nodeInfoActuallyChanged {
		oldTag := c.Tag
		oldNodeInfo := c.nodeInfo

		c.nodeInfo = newNodeInfo
		c.Tag = c.buildNodeTag()

		if err := c.nodeManager.RemoveNode(oldTag); err != nil {
			log.Printf("%s RemoveNode error: %v", c.LogPrefix, err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return err
		}
		c.LogPrefix = c.logPrefix()
		c.syncCertTasks()

		// The inbound is rebuilt, so the relay has to follow it. A new tag means the
		// relay rules still point at the old inbound and must be rebuilt.
		if err := c.syncRelay(c.nodeInfo, newSubs, subscriptionChanged || oldTag != c.Tag, true); err != nil {
			log.Printf("%s syncRelay error: %v", c.LogPrefix, err)
			if oldTag != c.Tag {
				c.teardownRelay()
			}
		} else {
			relaySynced = true
		}

		if err := c.nodeManager.AddNode(newNodeInfo, c.Tag, c.config, c.nodePusher(), c.blockRules); err != nil {
			log.Printf("%s AddNode error: %v", c.LogPrefix, err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return err
		}

		if err := c.subManager.AddSubscriptions(newSubs, newNodeInfo, c.Tag); err != nil {
			log.Printf("%s AddSubscriptions error: %v", c.LogPrefix, err)
		}

		if oldTag != c.Tag {
			c.coreInstance.DeleteCounter(oldTag)
			if err := limiter.DeleteLimiter(oldTag); err != nil {
				return fmt.Errorf("DeleteLimiter: %w", err)
			}
			if err := limiter.AddLimiter(c.Tag, newNodeInfo.UpdateInterval, newNodeInfo.SpeedLimit, newNodeInfo.IgnoreIPs, newSubs); err != nil {
				log.Printf("%s AddLimiter error: %v", c.LogPrefix, err)
			}
		} else {
			if err := limiter.UpdateNodeInfo(c.Tag, newNodeInfo.SpeedLimit, newNodeInfo.IgnoreIPs); err != nil {
				log.Printf("%s UpdateNodeInfo error: %v", c.LogPrefix, err)
			}

			deleted, added, modified := subscription.CompareSubscriptions(c.subscriptionList, newSubs)
			if len(deleted) > 0 {
				limiter.RemoveSubscriptions(oldTag, subscription.GetEmails(deleted, oldTag))
			}
			if len(added) > 0 {
				if err := limiter.UpdateLimiter(oldTag, &added); err != nil {
					log.Printf("%s UpdateLimiter (added): %v", c.LogPrefix, err)
				}
			}
			if len(modified) > 0 {
				limiter.RemoveSubscriptions(oldTag, subscription.GetEmails(modified, oldTag))
				if err := limiter.UpdateLimiter(oldTag, &modified); err != nil {
					log.Printf("%s UpdateLimiter (modified): %v", c.LogPrefix, err)
				}
			}
		}

		newInterval := c.pollInterval()
		if c.currentPollInterval != newInterval {
			for _, tag := range []string{"node", "subscriptions", "rules"} {
				if t := c.taskManager.GetTask(tag); t != nil {
					if err := t.RestartWithInterval(newInterval); err != nil {
						log.Printf("%s restart task %s: %v", c.LogPrefix, tag, err)
					}
				}
			}
			c.currentPollInterval = newInterval
			select {
			case c.intervalChangeCh <- newInterval:
			default:
			}
		}
	} else {
		if nodeInfoChanged {
			c.nodeInfo = newNodeInfo
			c.syncCertTasks()

			if err := limiter.UpdateNodeInfo(c.Tag, newNodeInfo.SpeedLimit, newNodeInfo.IgnoreIPs); err != nil {
				log.Printf("%s UpdateNodeInfo error: %v", c.LogPrefix, err)
			}

			newInterval := c.pollInterval()
			if c.currentPollInterval != newInterval {
				for _, tag := range []string{"node", "subscriptions", "rules"} {
					if t := c.taskManager.GetTask(tag); t != nil {
						if err := t.RestartWithInterval(newInterval); err != nil {
							log.Printf("%s restart task %s: %v", c.LogPrefix, tag, err)
						}
					}
				}
				c.currentPollInterval = newInterval
				select {
				case c.intervalChangeCh <- newInterval:
				default:
				}
			}
		}

		if subscriptionChanged {
			deleted, added, modified := subscription.CompareSubscriptions(c.subscriptionList, newSubs)

			if len(deleted) > 0 {
				emails := subscription.GetEmails(deleted, c.Tag)
				if err := c.subManager.RemoveSubscriptions(emails, c.Tag, c.nodeInfo.Protocol); err != nil {
					log.Printf("%s RemoveSubscriptions error: %v", c.LogPrefix, err)
				} else {
					limiter.RemoveSubscriptions(c.Tag, emails)
					log.Printf("%s removed %d subscription(s)", c.LogPrefix, len(deleted))
				}
			}
			if len(added) > 0 {
				if err := c.subManager.AddSubscriptions(&added, c.nodeInfo, c.Tag); err != nil {
					log.Printf("%s AddSubscriptions (new): %v", c.LogPrefix, err)
				} else {
					log.Printf("%s added %d subscription(s)", c.LogPrefix, len(added))
					if err := limiter.UpdateLimiter(c.Tag, &added); err != nil {
						log.Printf("%s UpdateLimiter (new): %v", c.LogPrefix, err)
					}
				}
			}
			if len(modified) > 0 {
				emails := subscription.GetEmails(modified, c.Tag)
				if err := c.subManager.RemoveSubscriptions(emails, c.Tag, c.nodeInfo.Protocol); err != nil {
					log.Printf("%s RemoveSubscriptions (modified): %v", c.LogPrefix, err)
				} else {
					limiter.RemoveSubscriptions(c.Tag, emails)
				}
				if err := c.subManager.AddSubscriptions(&modified, c.nodeInfo, c.Tag); err != nil {
					log.Printf("%s AddSubscriptions (modified): %v", c.LogPrefix, err)
				}
				if err := limiter.UpdateLimiter(c.Tag, &modified); err != nil {
					log.Printf("%s UpdateLimiter (modified): %v", c.LogPrefix, err)
				}
				log.Printf("%s modified %d subscription(s)", c.LogPrefix, len(modified))
			}
		}
	}

	// Runs on every poll, not only when subscriptions change. It is cheap when
	// nothing changed (no request), and it also retries a relay that failed to build.
	if err := c.syncRelay(c.nodeInfo, newSubs, !relaySynced && subscriptionChanged, !relaySynced && nodeInfoChanged); err != nil {
		log.Printf("%s syncRelay error: %v", c.LogPrefix, err)
	}

	c.subscriptionList = newSubs
	return nil
}

// teardownRelay removes the relay, rules first, then its outbounds.
func (c *Controller) teardownRelay() {
	if !c.Relay {
		return
	}
	if err := c.nodeManager.RemoveRelayRules(c.RelayTag, c.relaySubs); err != nil {
		log.Printf("%s RemoveRelayRules error: %v", c.LogPrefix, err)
	}
	if err := c.nodeManager.RemoveRelayTag(c.RelayTag, c.relaySubs); err != nil {
		log.Printf("%s RemoveRelayTag error: %v", c.LogPrefix, err)
	}
	c.Relay, c.RelayTag, c.relayNodeInfo, c.relaySubs = false, "", nil, nil
}

// sameRelay compares two transit infos. The port is ignored: GetTransitNode
// picks a random port from a range on every call.
func sameRelay(a, b *api.RelayNodeInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.Port, y.Port = 0, 0
	return reflect.DeepEqual(x, y)
}

// syncRelay makes the relay match the panel. subsChanged and infoChanged say
// what changed since the relay was built. A wanted relay that is missing, for
// example after an earlier failure, is built whatever the flags say.
// A new relay is built under a fresh tag before the old one is removed, so
// relayed users always have a relay rule.
func (c *Controller) syncRelay(info *api.NodeInfo, subs *[]api.SubscriptionInfo, subsChanged, infoChanged bool) error {
	if info.RelayType != 2 || info.RelayNodeID <= 0 {
		c.teardownRelay()
		return nil
	}
	if c.Relay && !subsChanged && !infoChanged {
		return nil
	}

	fresh, err := c.client.GetTransitNode()
	if err != nil {
		return fmt.Errorf("GetTransitNode: %w", err)
	}
	if c.Relay && !subsChanged && sameRelay(c.relayNodeInfo, fresh) {
		return nil // the node info changed, the transit server did not
	}

	oldTag, oldSubs, oldInfo, wasOn := c.RelayTag, c.relaySubs, c.relayNodeInfo, c.Relay
	if !wasOn {
		oldTag, oldSubs = "", nil
	}

	c.relayGen++
	c.relayNodeInfo = fresh
	newTag := c.buildRelayTag()

	if err := c.nodeManager.SwapRelay(oldTag, oldSubs, fresh, newTag, c.Tag, subs); err != nil {
		c.relayNodeInfo = oldInfo // the old relay keeps serving
		return fmt.Errorf("SwapRelay: %w", err)
	}
	c.RelayTag, c.relaySubs, c.Relay = newTag, subs, true
	return nil
}

func (c *Controller) ruleMonitor() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}

	rules, err := c.client.GetBlockRules()
	switch {
	case err == nil:
		c.pendingRules, c.hasPending = rules, true
	case err.Error() == api.RuleNotModified:
		if !c.hasPending {
			return nil
		}
		// An earlier apply failed, retry the rules we already fetched.
	default:
		log.Printf("%s GetBlockRules error: %v", c.LogPrefix, err)
		return err
	}

	if err := c.nodeManager.SetBlockRules(c.Tag, c.pendingRules); err != nil {
		log.Printf("%s SetBlockRules error: %v", c.LogPrefix, err)
		return err
	}
	c.blockRules = c.pendingRules
	c.pendingRules, c.hasPending = nil, false
	log.Printf("%s updated %d block rules", c.LogPrefix, len(c.blockRules))
	return nil
}

func (c *Controller) certMonitor() error {
	if c.nodeInfo.TlsSettings == nil {
		return nil
	}
	switch c.nodeInfo.TlsSettings.CertMode {
	case "dns":
		pn := c.config.CertConfig.Provider
		if c.nodeInfo.TlsSettings.DnsProvider != "" {
			pn = c.nodeInfo.TlsSettings.DnsProvider
		}
		if pn == "" {
			return fmt.Errorf("cert dns provider name is required")
		}
		lego, err := cert.NewForNode(c.config.CertConfig, pn)
		if err != nil {
			return err
		}
		if _, _, _, err := lego.RenewCert(c.nodeInfo.TlsSettings.CertMode, c.nodeInfo.TlsSettings.ServerName, c.nodeInfo.TlsSettings.CertEmail); err != nil {
			log.Printf("%s cert renew failed: %v", c.LogPrefix, err)
		}
	case "http", "tls":
		lego, err := cert.New(c.config.CertConfig)
		if err != nil {
			return fmt.Errorf("cert init: %w", err)
		}
		if _, _, _, err := lego.RenewCert(c.nodeInfo.TlsSettings.CertMode, c.nodeInfo.TlsSettings.ServerName, c.nodeInfo.TlsSettings.CertEmail); err != nil {
			log.Printf("%s cert renew failed: %v", c.LogPrefix, err)
		}
	}
	return nil
}

func (c *Controller) logPrefix() string {
	return fmt.Sprintf("[%s] %s(XMBox NodeID=%d)", c.clientInfo.APIHost, c.nodeInfo.Protocol, c.nodeInfo.ID)
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%d_%d", c.nodeInfo.Protocol, c.nodeInfo.ListenPort, c.nodeInfo.ID)
}

// buildRelayTag is unique per build (relayGen), so a new relay can be created
// next to the old one before the old one is removed.
func (c *Controller) buildRelayTag() string {
	return fmt.Sprintf("relay_%s_%d_%d_v%d", c.relayNodeInfo.NodeType, c.relayNodeInfo.Port, c.nodeInfo.RelayNodeID, c.relayGen)
}

// selfSignedCertMonitor generates a self-signed certificate and pushes its
// hashes to the panel via Reverb. It runs as its own scheduled task rather
// than being mixed into certMonitor's ACME/Lego flow.
func (c *Controller) selfSignedCertMonitor() error {
	info := c.nodeInfo
	if info == nil || info.TlsSettings == nil || info.TlsSettings.CertMode != "self-signed" {
		return nil
	}
	if _, _, err := node.SelfSignedCertFile(info.TlsSettings, c.nodePusher(), c.client); err != nil {
		log.Printf("%s self-signed cert renewal failed: %v", c.LogPrefix, err)
	}
	return nil
}