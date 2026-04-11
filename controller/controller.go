package controller

import (
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/core"
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
	core.SetControllerFactory(func(instance *core.Instance, nodeConfig *core.NodesConfig) service.ControllerInterface {
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
	coreInstance     *core.Instance
	config           *node.Config
	clientInfo       api.ClientInfo
	client           api.API
	nodeInfo         *api.NodeInfo
	Tag              string
	LogPrefix        string
	subscriptionList *[]api.SubscriptionInfo
	taskManager      *task.Manager
	nodeManager      *node.Manager
	subManager       *subscription.Manager
}

func New(coreInstance *core.Instance, api api.API, config *node.Config) *Controller {
	return &Controller{
		coreInstance: coreInstance,
		config:      config,
		client:      api,
		taskManager: task.NewManager(),
		nodeManager: node.NewManager(coreInstance),
		subManager:  subscription.NewManager(coreInstance, api),
	}
}

func (c *Controller) Start() error {
	c.clientInfo = c.client.Describe()

	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		log.Panic(err)
		return err
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	subscriptionInfo, err := c.client.GetSubscriptionList()
	if err != nil {
		log.Panic(err)
		return err
	}
	c.subscriptionList = subscriptionInfo

	if err = c.nodeManager.AddNode(c.nodeInfo, c.Tag, c.config); err != nil {
		return fmt.Errorf("Failed to add node: %w", err)
	}

	if err = c.subManager.AddSubscriptions(subscriptionInfo, newNodeInfo, c.Tag); err != nil {
		return err
	}
	log.Printf("%s Added %d subscriptions", c.logPrefix(), len(*subscriptionInfo))

	if err = limiter.AddLimiter(
		c.Tag,
		c.nodeInfo.UpdateInterval,
		newNodeInfo.SpeedLimit,
		subscriptionInfo,
		c.config.RedisConfig,
	); err != nil {
		log.Print(err)
	}
	
	if ruleList, err := c.client.GetNodeRule(); err != nil {
		log.Printf("Get rule list filed: %s", err)
	} else if len(*ruleList) > 0 {
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Print(err)
		}
	}

	c.LogPrefix = c.logPrefix()

	c.taskManager.Add(task.NewWithInterval(
		c.LogPrefix,
		"server",
		time.Duration(c.nodeInfo.UpdateInterval)*time.Second,
		c.nodeInfoMonitor,
	))

	c.taskManager.Add(task.NewWithInterval(
		c.LogPrefix,
		"subscriptions",
		time.Duration(c.nodeInfo.UpdateInterval)*time.Second,
		func() error {
			return c.subManager.SubscriptionMonitor(c.subscriptionList, c.Tag, c.LogPrefix)
		},
	))

	if c.nodeInfo.TlsSettings != nil && c.nodeInfo.TlsSettings.Type == "tls" {
		c.taskManager.Add(task.NewWithDelay(
			c.LogPrefix,
			"cert renew",
			time.Duration(c.nodeInfo.UpdateInterval)*time.Second*60,
			c.certMonitor,
		))
	}

	log.Printf("%s Starting %d task schedulers", c.logPrefix(), c.taskManager.Count())
	return c.taskManager.StartAll()
}

func (c *Controller) Close() error {
	log.Printf("%s Closing %d task schedulers", c.logPrefix(), c.taskManager.Count())
	return c.taskManager.CloseAll()
}

func (c *Controller) certMonitor() error {
    switch c.nodeInfo.TlsSettings.CertMode {
    case "dns", "http", "tls":
        lego, err := cert.New(c.config.CertConfig)
        if err != nil {
            log.Printf("%s cert init failed: %v", c.LogPrefix, err)
            return err
        }
        if _, _, _, err = lego.RenewCert(
            c.nodeInfo.TlsSettings.CertMode,
            c.nodeInfo.TlsSettings.ServerName,
        ); err != nil {
            log.Printf("%s cert renew failed: %v", c.LogPrefix, err)
            return err
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

func (c *Controller) nodeInfoMonitor() error {
	var err error

	var nodeInfoChanged = true
	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			log.Panic(err)
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
			log.Panic(err)
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
			log.Panic(err)
		}

		if err = c.nodeManager.AddNode(newNodeInfo, c.Tag, c.config); err != nil {
			log.Panic(err)
			c.nodeInfo, c.Tag = oldNodeInfo, oldTag
			return nil
		}

		if err = c.subManager.AddSubscriptions(newSubscriptionInfo, newNodeInfo, c.Tag); err != nil {
			log.Panic(err)
			return nil
		}

		if err = limiter.AddLimiter(
			c.Tag,
			newNodeInfo.UpdateInterval,
			newNodeInfo.SpeedLimit,
			newSubscriptionInfo,
			c.config.RedisConfig,
		); err != nil {
			log.Panic(err)
			return nil
		}
	} else if subscriptionChanged {
		deleted, added, modified := subscription.CompareSubscriptions(c.subscriptionList, newSubscriptionInfo)

		if len(deleted) > 0 {
			deletedUUID := subscription.GetUUIDs(deleted)
			if err = c.subManager.RemoveSubscriptions(deletedUUID, c.Tag, c.nodeInfo.Protocol); err != nil {
				log.Printf("%s Error removing subscriptions: %v", c.LogPrefix, err)
			} else {
				limiter.RemoveSubscriptions(c.Tag, deletedUUID)
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
			}
		}

		if len(modified) > 0 {
			deletedUUID := subscription.GetUUIDs(modified)
			if err = c.subManager.RemoveSubscriptions(deletedUUID, c.Tag, c.nodeInfo.Protocol); err != nil {
				log.Printf("%s Error removing modified subscriptions: %v", c.LogPrefix, err)
			} else {
				limiter.RemoveSubscriptions(c.Tag, deletedUUID)
			}
			if err = c.subManager.AddSubscriptions(&modified, c.nodeInfo, c.Tag); err != nil {
				log.Printf("%s Error adding modified subscriptions: %v", c.LogPrefix, err)
			}
			if err = limiter.UpdateLimiter(c.Tag, &modified); err != nil {
				log.Printf("%s Error updating limiter for modified subscriptions: %v", c.LogPrefix, err)
			}
			
			log.Printf("%s Modified %d subscription(s)", c.LogPrefix, len(modified))
		}
	}
	
	var ruleChanged = true
	ruleList, err := c.client.GetNodeRule()
	if err != nil {
		if err.Error() == api.RuleNotModified {
			ruleChanged = false
		} else {
			log.Printf("%s Failed to get rule list: %s", c.LogPrefix, err)
			return nil
		}
	}

	if ruleChanged && ruleList != nil && len(*ruleList) > 0 {
		log.Printf("%s Updating %d node rules", c.LogPrefix, len(*ruleList))
		if err := rule.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Printf("%s Failed to update rules: %s", c.LogPrefix, err)
		}
	}

	c.subscriptionList = newSubscriptionInfo
	return nil
}