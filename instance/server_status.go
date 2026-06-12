package instance

import (
	"encoding/json"
	"log"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/monitor"
	"github.com/xmplusdev/xmbox/scheduler"
)

const serverStatusReportInterval = 5 * time.Second

// startServerStatusTask launches a periodic task that collects server stats
// and reports them to the panel every 5 seconds.
func (i *Instance) startServerStatusTask(rootClient api.API) {
	task := scheduler.New(
		"[ServerStatus]",
		"server_status",
		serverStatusReportInterval,
		func() error {
			return i.reportServerStatus(rootClient)
		},
	)
	i.serverStatusTask = task

	go func() {
		if err := task.Start(); err != nil {
			log.Printf("[ServerStatus] task start error: %v", err)
		}
	}()
}

// reportServerStatus collects server metrics and pushes them to the panel.
// It tries the active Reverb WebSocket first; on failure it falls back to HTTP.
func (i *Instance) reportServerStatus(rootClient api.API) error {
	status, err := monitor.Collect()
	if err != nil {
		log.Printf("[ServerStatus] collect error: %v", err)
		return err
	}

	serverID := i.instanceConfig.ApiConfig.ServerID

	// Attempt push via Reverb
	i.mu.Lock()
	pusher := i.currentPusher
	i.mu.Unlock()

	if pusher != nil {
		payload := api.ServerStatusPayload{
			ServerID: serverID,
			Data:     status,
		}
		b, _ := json.Marshal(payload)
		var data any
		_ = json.Unmarshal(b, &data)
		if err := pusher("server_status", data); err == nil {
			return nil
		}
		// Fall through to HTTP
	}

	// HTTP fallback
	return rootClient.ReportServerStatus(serverID, status)
}
