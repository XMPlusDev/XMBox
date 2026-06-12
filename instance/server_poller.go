package instance

import (
	"log"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/scheduler"
	"github.com/xmplusdev/xmbox/service"
)

const defaultServerPollInterval = 60 // seconds

// startServerNodePoller launches a periodic task that re-syncs the machine's
// node list from the panel.  An immediate sync is also triggered when the
// serverPollTrigger channel fires (e.g. from a "server_updated" Reverb event).
func (i *Instance) startServerNodePoller(rootClient api.API, pollInterval int) {
	if pollInterval <= 0 {
		pollInterval = defaultServerPollInterval
	}
	interval := time.Duration(pollInterval) * time.Second

	task := scheduler.NewWithDelay(
		"[ServerMode]",
		"node_poller",
		interval,
		func() error {
			return i.syncServerNodes(rootClient)
		},
	)
	i.serverPoller = task

	go func() {
		if err := task.Start(); err != nil {
			log.Printf("[ServerMode] node poller start error: %v", err)
		}
	}()

	// Watch for instant triggers (Reverb server_updated event)
	go func() {
		for {
			select {
			case _, ok := <-i.serverPollTrigger:
				if !ok {
					return
				}
				log.Println("[ServerMode] instant node sync triggered")
				if err := i.syncServerNodes(rootClient); err != nil {
					log.Printf("[ServerMode] instant sync error: %v", err)
				}
			}
		}
	}()
}

// syncServerNodes fetches the current node list from the panel and reconciles
// it against the running controllers: new nodes are started, removed nodes are stopped.
func (i *Instance) syncServerNodes(rootClient api.API) error {
	resp, err := rootClient.GetServerNodes()
	if err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Index desired nodes
	desired := make(map[int]struct{}, len(resp.Nodes))
	for _, n := range resp.Nodes {
		desired[n.NodeID] = struct{}{}
	}

	// Stop controllers for nodes that are no longer in the list
	for nodeID, svc := range i.controllerMap {
		if _, ok := desired[nodeID]; !ok {
			log.Printf("[ServerMode] removing node %d", nodeID)
			if err := svc.(service.ControllerInterface).Close(); err != nil {
				log.Printf("[ServerMode] error closing node %d: %v", nodeID, err)
			}
			// Remove from service slice
			for j, s := range i.Service {
				if t, ok := s.(service.TriggerInterface); ok && t.GetNodeID() == nodeID {
					i.Service = append(i.Service[:j], i.Service[j+1:]...)
					break
				}
			}
			delete(i.controllerMap, nodeID)
		}
	}

	// Start controllers for newly added nodes
	for _, n := range resp.Nodes {
		if _, running := i.controllerMap[n.NodeID]; running {
			continue
		}
		log.Printf("[ServerMode] adding node %d", n.NodeID)
		nc := &NodesConfig{
			ApiConfig: &api.Config{
				APIHost:  i.instanceConfig.ApiConfig.APIHost,
				NodeID:   n.NodeID,
				APIKey:   i.instanceConfig.ApiConfig.APIKey,
				Timeout:  i.instanceConfig.ApiConfig.Timeout,
				ServerID: i.instanceConfig.ApiConfig.ServerID,
			},
			CertConfig: i.instanceConfig.CertConfig,
		}
		svc := globalFactory(i, nc)
		if err := svc.Start(); err != nil {
			log.Printf("[ServerMode] failed to start node %d: %v", n.NodeID, err)
			continue
		}
		i.Service = append(i.Service, svc)
		if t, ok := svc.(service.TriggerInterface); ok {
			i.controllerMap[t.GetNodeID()] = t
		}
	}

	return nil
}
