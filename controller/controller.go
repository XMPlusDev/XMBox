package controller

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/core/instance"
	"github.com/xmplusdev/xmbox/helper/cert"
	"github.com/xmplusdev/xmbox/helper/rule"
	"github.com/xmplusdev/xmbox/helper/limiter"
	"github.com/xmplusdev/xmbox/helper/task"
	"github.com/xmplusdev/xmbox/node"
	"github.com/xmplusdev/xmbox/subscription"
	"github.com/xmplusdev/xmbox/service"
)

func getDefaultControllerConfig() *node.Config {
	return &node.Config{}
}

var _ service.ControllerInterface = (*Controller)(nil)

func init() {
	instance.SetControllerFactory(func(instance *instance.Instance, nodeConfig *instance.NodesConfig) service.ControllerInterface {
		apiClient := api.New(nodeConfig.ApiConfig)
		cfg := getDefaultControllerConfig()
		if nodeConfig != nil {
			cfg.CertConfig = nodeConfig.CertConfig
			cfg.RedisConfig = nodeConfig.RedisConfig
		}
		return New(instance, apiClient, cfg)
	})
}

type Controller struct {
	coreInstance        *instance.Instance
	config              *node.Config
	clientInfo          api.ClientInfo
	client              api.API
	nodeInfo            *api.NodeInfo
	Tag                 string
	LogPrefix           string
	currentPollInterval time.Duration
	subscriptionList    *[]api.SubscriptionInfo
	taskManager         *task.Manager
	nodeManager         *node.Manager
	subManager          *subscription.Manager

	nodeSyncTrigger         chan struct{}
	subscriptionSyncTrigger chan struct{}
	intervalChangeCh        chan time.Duration
	triggerCtx              context.Context
	triggerCancel           context.CancelFunc
}

func New(coreInstance *instance.Instance, api api.API, config *node.Config) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		coreInstance:            coreInstance,
		config:                  config,
		client:                  api,
		taskManager:             task.NewManager(),
		nodeManager:             node.NewManager(coreInstance),
		subManager:              subscription.NewManager(coreInstance, api),
		nodeSyncTrigger:         make(chan struct{}, 1),
		subscriptionSyncTrigger: make(chan struct{}, 1),
		intervalChangeCh:        make(chan time.Duration, 1),
		triggerCtx:              ctx,
		triggerCancel:           cancel,
	}
}

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

func (c *Controller) GetNodeID() int {
	return c.clientInfo.NodeID
}

func (c *Controller) Start() error {
	c.clientInfo = c.client.Describe()

	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("Controller GetNodeInfo: %w", err)
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()
	c.LogPrefix = c.logPrefix()

	if ruleList, err := c.client.GetNodeRule(); err != nil {
		log.Printf("Get rule list filed: %s", err)
	} else if len(*ruleList) > 0 {
		log.Printf("%s Added %d node rules", c.LogPrefix, len(*ruleList))
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			return fmt.Errorf("Controller GetNodeRule: %w", err)
		}
	}

	subscriptionInfo, err := c.client.GetSubscriptionList()
	if err != nil {
		return fmt.Errorf("Controller GetSubscriptionList: %w", err)
	}
	c.subscriptionList = subscriptionInfo

	if err = c.nodeManager.AddNode(c.nodeInfo, c.Tag, c.config); err != nil {
		return fmt.Errorf("Failed to add node: %w", err)
	}

	if err = c.subManager.AddSubscriptions(subscriptionInfo, newNodeInfo, c.Tag); err != nil {
		return fmt.Errorf("Controller AddSubscriptions: %w", err)
	}
	log.Printf("%s Added %d subscriptions", c.LogPrefix, len(*subscriptionInfo))

	if err = limiter.AddLimiter(
		c.Tag,
		c.nodeInfo.UpdateInterval,
		newNodeInfo.SpeedLimit,
		subscriptionInfo,
		c.config.RedisConfig,
	); err != nil {
		fmt.Errorf("Controller AddLimiter: %w", err)
	}

	c.checkAndCloseExceeded()

	c.currentPollInterval = c.pollInterval()

	c.taskManager.Add(task.NewWithDelay(
		c.LogPrefix,
		"node",
		c.currentPollInterval,
		c.apiMonitor,
	))

	c.taskManager.Add(task.NewWithDelay(
		c.LogPrefix,
		"subscriptions",
		c.currentPollInterval,
		func() error {
			return c.subManager.SubscriptionMonitor(c.Tag, c.LogPrefix)
		},
	))

	c.taskManager.Add(task.NewWithDelay(
		c.LogPrefix,
		"rules",
		c.currentPollInterval,
		c.ruleMonitor,
	))

	if c.nodeInfo.TlsSettings != nil && c.nodeInfo.TlsSettings.Type == "tls" {
		c.taskManager.Add(task.NewWithDelay(
			c.LogPrefix,
			"cert renew",
			c.currentPollInterval*60,
			c.certMonitor,
		))
	}

	go c.webhookTriggerLoop(c.currentPollInterval)

	log.Printf("%s Starting %d task schedulers", c.LogPrefix, c.taskManager.Count())
	return c.taskManager.StartAll()
}

func (c *Controller) Close() error {
	log.Printf("%s Closing %d task schedulers", c.LogPrefix, c.taskManager.Count())

	c.triggerCancel()

	return c.taskManager.CloseAll()
}

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
			log.Printf("%s Webhook interval updated to %v", c.LogPrefix, newInterval)

		case <-c.nodeSyncTrigger:
			if time.Since(lastSync) < debounceDuration {
				log.Printf("%s Webhook node trigger debounced", c.LogPrefix)
				c.drainChannel(c.nodeSyncTrigger)
				continue
			}
			log.Printf("%s Webhook node trigger: syncing now", c.LogPrefix)
			if err := c.apiMonitor(); err != nil {
				log.Printf("%s Webhook node sync error: %v", c.LogPrefix, err)
			}
			lastSync = time.Now()
			c.drainChannel(c.nodeSyncTrigger)
			ticker.Reset(fallbackInterval)

		case <-c.subscriptionSyncTrigger:
			if time.Since(lastSync) < debounceDuration {
				log.Printf("%s Webhook subscription trigger debounced", c.LogPrefix)
				c.drainChannel(c.subscriptionSyncTrigger)
				continue
			}
			log.Printf("%s Webhook subscription trigger: syncing now", c.LogPrefix)
			if err := c.apiMonitor(); err != nil {
				log.Printf("%s Webhook subscription sync error: %v", c.LogPrefix, err)
			}
			lastSync = time.Now()
			c.drainChannel(c.subscriptionSyncTrigger)
			ticker.Reset(fallbackInterval)

		case <-ticker.C:
			lastSync = time.Now()
		}
	}
}

func (c *Controller) drainChannel(ch chan struct{}) {
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

func (c *Controller) apiMonitor() error {
	var err error

	var nodeInfoChanged = true
	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			fmt.Errorf("Controller NodeInfoMonitor GetNodeInfo: %w", err)
			return nil
		}
	}

	var subscriptionChanged = true
	newSubscriptionInfo, err := c.client.GetSubscriptionList()
	if err != nil {
		if err.Error() == api.SubscriptionNotModified {
			subscriptionChanged = false
			newSubscriptionInfo = c.subscriptionList
		} else {
			fmt.Errorf("Controller NodeInfoMonitor GetSubscriptionList: %w", err)
			return nil
		}
	}

	if nodeInfoChanged && !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {

		oldTag := c.Tag
		oldNodeInfo := c.nodeInfo

		c.nodeInfo = newNodeInfo
		c.Tag = c.buildNodeTag()

		if err = c.nodeManager.RemoveNode(oldTag); err != nil {
			log.Printf("%s Failed to remove node: %v", c.LogPrefix, err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return err
		}
		c.coreInstance.DeleteCounter(oldTag)
		if err = limiter.DeleteLimiter(oldTag); err != nil {
			fmt.Errorf("Controller NodeInfoMonitor DeleteLimiter: %w", err)
		}

		if err = c.nodeManager.AddNode(newNodeInfo, c.Tag, c.config); err != nil {
			fmt.Errorf("Controller NodeInfoMonitor AddNode: %w", err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return nil
		}

		if err = c.subManager.AddSubscriptions(newSubscriptionInfo, newNodeInfo, c.Tag); err != nil {
			fmt.Errorf("Controller NodeInfoMonitor AddSubscriptions: %w", err)
			return nil
		}

		if err = limiter.AddLimiter(
			c.Tag,
			newNodeInfo.UpdateInterval,
			newNodeInfo.SpeedLimit,
			newSubscriptionInfo,
			c.config.RedisConfig,
		); err != nil {
			fmt.Errorf("Controller NodeInfoMonitor AddLimiter: %w", err)
			return nil
		}

		newInterval := c.pollInterval()
		if c.currentPollInterval != newInterval {
			for _, tag := range []string{"node", "subscriptions", "rules"} {
				if t := c.taskManager.GetTask(tag); t != nil {
					if err := t.RestartWithInterval(newInterval); err != nil {
						log.Printf("%s Failed to restart %s task: %v", c.LogPrefix, tag, err)
					} else {
						log.Printf("%s %s task  restarted with interval %v", c.LogPrefix, tag, newInterval)
					}
				}
			}

			c.currentPollInterval = newInterval

			select {
			case c.intervalChangeCh <- newInterval:
			default:
			}
		}

		c.checkAndCloseExceeded()
	} else if subscriptionChanged {
		deleted, added, modified := subscription.CompareSubscriptions(c.subscriptionList, newSubscriptionInfo)

		if len(deleted) > 0 {
			deletedEmails := subscription.GetEmails(deleted, c.Tag)
			if err = c.subManager.RemoveSubscriptions(deletedEmails, c.Tag, c.nodeInfo.Protocol); err != nil {
				log.Printf("%s Error removing subscriptions: %v", c.LogPrefix, err)
			} else {
				limiter.RemoveSubscriptions(c.Tag, deletedEmails)
				log.Printf("%s Removed %d subscription(s)", c.LogPrefix, len(deleted))
			}
		}

		if len(added) > 0 {
			if err = c.subManager.AddSubscriptions(&added, c.nodeInfo, c.Tag); err != nil {
				log.Printf("%s Error adding subscriptions: %v", c.LogPrefix, err)
			} else {
				log.Printf("%s Added %d subscription(s)", c.LogPrefix, len(added))
				if err = limiter.UpdateLimiter(c.Tag, &added); err != nil {
					log.Printf("%s Error updating limiter for new subscriptions: %v", c.LogPrefix, err)
				}
				c.checkAndCloseExceeded()
			}
		}

		if len(modified) > 0 {
			deletedEmails := subscription.GetEmails(modified, c.Tag)
			if err = c.subManager.RemoveSubscriptions(deletedEmails, c.Tag, c.nodeInfo.Protocol); err != nil {
				log.Printf("%s Error removing modified subscriptions: %v", c.LogPrefix, err)
			} else {
				limiter.RemoveSubscriptions(c.Tag, deletedEmails)
			}
			if err = c.subManager.AddSubscriptions(&modified, c.nodeInfo, c.Tag); err != nil {
				log.Printf("%s Error adding modified subscriptions: %v", c.LogPrefix, err)
			}
			if err = limiter.UpdateLimiter(c.Tag, &modified); err != nil {
				log.Printf("%s Error updating limiter for modified subscriptions: %v", c.LogPrefix, err)
			}
			c.checkAndCloseExceeded()
			log.Printf("%s Modified %d subscription(s)", c.LogPrefix, len(modified))
		}
	}

	c.subscriptionList = newSubscriptionInfo
	return nil
}

func (c *Controller) checkAndCloseExceeded() {
	exceeded := limiter.CheckTrafficExceeded(c.Tag)
	for _, email := range exceeded {
		c.coreInstance.GetDispatcher().CloseUserConns(c.Tag, email)
		log.Printf("%s Traffic quota exhausted, closing connections for email=%s", c.LogPrefix, email)
	}
}

func (c *Controller) ruleMonitor() error {
	ruleList, err := c.client.GetNodeRule()
	if err != nil {
		if err.Error() == api.RuleNotModified {
			return nil
		}
		log.Printf("%s Failed to get rule list: %s", c.LogPrefix, err)
		return err
	}
	if ruleList != nil && len(*ruleList) > 0 {
		log.Printf("%s Updating %d node rules", c.LogPrefix, len(*ruleList))
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Printf("%s Failed to update rules: %s", c.LogPrefix, err)
			return err
		}
	}
	return nil
}

func (c *Controller) certMonitor() error {
	switch c.nodeInfo.TlsSettings.CertMode {
	case "dns", "http", "tls":
		lego, err := cert.New(c.config.CertConfig)
		if err != nil {
			log.Printf("%s cert init failed: %v", c.LogPrefix, err)
			return fmt.Errorf("Controller CertMonitor Init: %w", err)
		}
		if _, _, _, err = lego.RenewCert(
			c.nodeInfo.TlsSettings.CertMode,
			c.nodeInfo.TlsSettings.ServerName,
		); err != nil {
			log.Printf("%s cert renew failed: %v", c.LogPrefix, err)
			return fmt.Errorf("Controller CertMonitor Renew: %w", err)
		}
	}
	return nil
}

func (c *Controller) logPrefix() string {
	return fmt.Sprintf("[%s] %s(NodeID=%d)",
		c.clientInfo.APIHost,
		c.nodeInfo.Protocol,
		c.nodeInfo.ID)
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%d_%d",
		c.nodeInfo.Protocol,
		c.nodeInfo.ListenPort,
		c.nodeInfo.ID)
}