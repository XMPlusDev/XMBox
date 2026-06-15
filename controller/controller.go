package controller

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/cert"
	"github.com/xmplusdev/xmbox/instance"
	"github.com/xmplusdev/xmbox/limiter"
	"github.com/xmplusdev/xmbox/node"
	"github.com/xmplusdev/xmbox/rule"
	"github.com/xmplusdev/xmbox/scheduler"
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

// Controller manages one node: fetching config, managing subscriptions, reporting traffic.
type Controller struct {
	coreInstance *instance.Instance
	config       *node.Config
	clientInfo   api.ClientInfo
	client       api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	LogPrefix    string

	currentPollInterval time.Duration
	subscriptionList    *[]api.SubscriptionInfo

	relayNodeInfo *api.RelayNodeInfo
	RelayTag      string
	Relay         bool

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
}

// New constructs a Controller.  pusher may be nil.
func New(coreInstance *instance.Instance, apiClient api.API, config *node.Config) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		coreInstance:            coreInstance,
		config:                  config,
		client:                  apiClient,
		taskManager:             scheduler.NewManager(),
		nodeManager:             node.NewManager(coreInstance),
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
			"node_id": nodeID,
			"data":    data,
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

	if ruleList, err := c.client.GetNodeRule(); err != nil {
		log.Printf("%s get rule list failed: %v", c.LogPrefix, err)
	} else if ruleList != nil && len(*ruleList) > 0 {
		log.Printf("%s added %d node rules", c.LogPrefix, len(*ruleList))
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			return fmt.Errorf("UpdateRule: %w", err)
		}
	}

	subscriptions, err := c.client.GetSubscriptionList()
	if err != nil {
		return fmt.Errorf("GetSubscriptionList: %w", err)
	}
	c.subscriptionList = subscriptions

	if err := c.nodeManager.AddNode(c.nodeInfo, c.Tag, c.config); err != nil {
		return fmt.Errorf("AddNode: %w", err)
	}

	if err := c.subManager.AddSubscriptions(subscriptions, nodeInfo, c.Tag); err != nil {
		return fmt.Errorf("AddSubscriptions: %w", err)
	}
	log.Printf("%s added %d subscriptions", c.LogPrefix, len(*subscriptions))

	if err := c.setupRelay(c.nodeInfo, c.subscriptionList); err != nil {
		return fmt.Errorf("setupRelay: %w", err)
	}

	// AddLimiter no longer takes a RedisConfig — the global client is already
	// initialised at instance start via limiter.Init().
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

	if c.nodeInfo.TlsSettings != nil && c.nodeInfo.TlsSettings.Type == "tls" {
		c.taskManager.Add(scheduler.NewWithDelay(c.LogPrefix, "cert_renew",
			c.currentPollInterval*60, c.certMonitor))
	}

	go c.webhookTriggerLoop(c.currentPollInterval)

	log.Printf("%s starting %d task schedulers", c.LogPrefix, c.taskManager.Count())
	return c.taskManager.StartAll()
}

func (c *Controller) Close() error {
	log.Printf("%s closing %d task schedulers", c.LogPrefix, c.taskManager.Count())
	c.triggerCancel()
	if err := limiter.DeleteLimiter(c.Tag); err != nil {
		log.Printf("%s DeleteLimiter error: %v", c.LogPrefix, err)
	}
	if err := c.nodeManager.RemoveNode(c.Tag); err != nil {
		log.Printf("%s Close RemoveNode error: %v", c.LogPrefix, err)
	}
	if c.Relay {
		if err := c.nodeManager.RemoveRelayRules(c.RelayTag, c.subscriptionList); err != nil {
			log.Printf("%s Close RemoveRelayRules error: %v", c.LogPrefix, err)
		}
		if err := c.nodeManager.RemoveRelayTag(c.RelayTag, c.subscriptionList); err != nil {
			log.Printf("%s Close RemoveRelayTag error: %v", c.LogPrefix, err)
		}
	}
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

// apiMonitor fetches updated node info and subscription list, then reconciles
// the running state accordingly.
func (c *Controller) apiMonitor() error {
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

	nodeInfoActuallyChanged := nodeInfoChanged && !reflect.DeepEqual(c.nodeInfo, newNodeInfo)

	if c.Relay && (nodeInfoActuallyChanged || subscriptionChanged) {
		if err := c.nodeManager.RemoveRelayRules(c.RelayTag, c.subscriptionList); err != nil {
			log.Printf("%s RemoveRelayRules error: %v", c.LogPrefix, err)
		}
		if err := c.nodeManager.RemoveRelayTag(c.RelayTag, c.subscriptionList); err != nil {
			log.Printf("%s RemoveRelayTag error: %v", c.LogPrefix, err)
		}
		c.Relay = false
		c.RelayTag = ""
		c.relayNodeInfo = nil
	}

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

		if err := c.nodeManager.AddNode(newNodeInfo, c.Tag, c.config); err != nil {
			log.Printf("%s AddNode error: %v", c.LogPrefix, err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return err
		}

		if err := c.subManager.AddSubscriptions(newSubs, newNodeInfo, c.Tag); err != nil {
			log.Printf("%s AddSubscriptions error: %v", c.LogPrefix, err)
		}

		if err := c.setupRelay(newNodeInfo, newSubs); err != nil {
			log.Printf("%s setupRelay error: %v", c.LogPrefix, err)
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
	} else if subscriptionChanged {
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

		if err := c.setupRelay(c.nodeInfo, newSubs); err != nil {
			log.Printf("%s setupRelay error: %v", c.LogPrefix, err)
		}
	}

	c.subscriptionList = newSubs
	return nil
}

// setupRelay configures per-subscription relay outbounds and routing rules
// when nodeInfo declares a transit (relay) node. It is a no-op if no relay is
// configured, or if relay is already set up for the current RelayTag.
func (c *Controller) setupRelay(nodeInfo *api.NodeInfo, subscriptions *[]api.SubscriptionInfo) error {
	if nodeInfo.RelayType != 2 || nodeInfo.RelayNodeID <= 0 {
		return nil
	}
	if c.Relay {
		return nil
	}

	relayNodeInfo, err := c.client.GetTransitNode()
	if err != nil {
		return fmt.Errorf("GetTransitNode: %w", err)
	}
	c.relayNodeInfo = relayNodeInfo
	c.RelayTag = c.buildRelayTag()

	if err := c.nodeManager.AddRelayTag(relayNodeInfo, c.RelayTag, c.Tag, subscriptions); err != nil {
		return fmt.Errorf("AddRelayTag: %w", err)
	}
	c.Relay = true
	log.Printf("%s added relay tag %s -> %s:%d (%s)", c.LogPrefix, c.RelayTag, relayNodeInfo.Address, relayNodeInfo.Port, relayNodeInfo.NodeType)
	return nil
}

func (c *Controller) ruleMonitor() error {
	ruleList, err := c.client.GetNodeRule()
	if err != nil {
		if err.Error() == api.RuleNotModified {
			return nil
		}
		log.Printf("%s GetNodeRule error: %v", c.LogPrefix, err)
		return err
	}
	if ruleList != nil && len(*ruleList) > 0 {
		log.Printf("%s updating %d node rules", c.LogPrefix, len(*ruleList))
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Printf("%s UpdateRule error: %v", c.LogPrefix, err)
		}
	}
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
		if _,_, _, err := lego.RenewCert(c.nodeInfo.TlsSettings.CertMode, c.nodeInfo.TlsSettings.ServerName, c.nodeInfo.TlsSettings.CertEmail); err != nil {
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

func (c *Controller) buildRelayTag() string {
	return fmt.Sprintf("relay_%s_%d_%d", c.relayNodeInfo.NodeType, c.relayNodeInfo.Port, c.nodeInfo.RelayNodeID)
}
