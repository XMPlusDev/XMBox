package instance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// reverbOutbound is a message queued to be pushed to the panel via Reverb.
type reverbOutbound struct {
	event  string
	data   any
	result chan error
}

type pusherMessage struct {
	Event   string          `json:"event"`
	Channel string          `json:"channel,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type pusherEventData struct {
	NodeID int    `json:"node_id"`
	Event  string `json:"event"`
}

type pusherConnected struct {
	SocketID        string `json:"socket_id"`
	ActivityTimeout int    `json:"activity_timeout"`
}

const reverbChannel = "private-xmplus"

// reverbSession state — one per active connection, shared for outbound push.
type reverbSession struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	closed bool
}

func (s *reverbSession) push(event string, data any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	msg := pusherMessage{
		Event:   "client-" + event,
		Channel: reverbChannel,
		Data:    payload,
	}
	b, _ := json.Marshal(msg)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("reverb session closed")
	}
	return s.conn.WriteMessage(websocket.TextMessage, b)
}

// reverbListener maintains a persistent WebSocket connection to a Reverb server.
func (i *Instance) reverbListener(ctx context.Context, cfg *ReverbConfig) {
	scheme := "ws"
	if cfg.UseTLS {
		scheme = "wss"
	}
	url := fmt.Sprintf("%s://%s/app/%s?protocol=7&client=go&version=1.0", scheme, cfg.Host, cfg.AppKey)

	const (
		initialBackoff = 2 * time.Second
		maxBackoff     = 60 * time.Second
		pingInterval   = 25 * time.Second
	)
	backoff := initialBackoff

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[Reverb] connecting to %s channel=%s", cfg.Host, reverbChannel)
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, url, http.Header{})
		if err != nil {
			log.Printf("[Reverb] connect error: %v — retrying in %s", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}

		log.Printf("[Reverb] connected to %s", cfg.Host)
		backoff = initialBackoff

		sess := &reverbSession{conn: conn}

		// Register this session as the current pusher
		i.mu.Lock()
		i.currentPusher = sess.push
		i.mu.Unlock()

		if err := i.runReverbSession(ctx, conn, cfg, pingInterval); err != nil {
			log.Printf("[Reverb] session ended: %v — reconnecting in %s", err, backoff)
		}

		// Unregister pusher on disconnect
		i.mu.Lock()
		i.currentPusher = nil
		sess.mu.Lock()
		sess.closed = true
		sess.mu.Unlock()
		i.mu.Unlock()

		conn.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = minDuration(backoff*2, maxBackoff)
	}
}

func (i *Instance) runReverbSession(ctx context.Context, conn *websocket.Conn, cfg *ReverbConfig, pingInterval time.Duration) error {
	socketID, err := awaitConnected(conn)
	if err != nil {
		return fmt.Errorf("await connected: %w", err)
	}

	subData := map[string]string{"channel": reverbChannel}
	if cfg.AppSecret != "" {
		subData["auth"] = signChannel(cfg.AppKey, cfg.AppSecret, socketID, reverbChannel)
	}
	sub, _ := json.Marshal(pusherMessage{
		Event: "pusher:subscribe",
		Data:  mustMarshal(subData),
	})
	if err := conn.WriteMessage(websocket.TextMessage, sub); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	ping := time.NewTicker(pingInterval)
	defer ping.Stop()

	readErr := make(chan error, 1)
	msgs := make(chan pusherMessage, 16)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			var msg pusherMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("[Reverb] malformed message: %v", err)
				continue
			}
			msgs <- msg
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil
		case err := <-readErr:
			return err
		case <-ping.C:
			p, _ := json.Marshal(pusherMessage{Event: "pusher:ping", Data: mustMarshal(map[string]any{})})
			if err := conn.WriteMessage(websocket.TextMessage, p); err != nil {
				return fmt.Errorf("ping: %w", err)
			}
		case msg := <-msgs:
			i.handleReverbMessage(msg, reverbChannel)
		}
	}
}

// handleReverbMessage dispatches incoming Reverb events to the appropriate controller.
func (i *Instance) handleReverbMessage(msg pusherMessage, channel string) {
	switch msg.Event {
	case "pusher:pong", "pusher_internal:subscription_succeeded", "pusher:connection_established":
		return
	}
	if msg.Channel != channel {
		return
	}

	var dataStr string
	var payload pusherEventData

	if err := json.Unmarshal(msg.Data, &dataStr); err == nil {
		if err := json.Unmarshal([]byte(dataStr), &payload); err != nil {
			log.Printf("[Reverb] failed to decode inner data: %v", err)
			return
		}
	} else {
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Printf("[Reverb] failed to decode data: %v", err)
			return
		}
	}

	switch payload.Event {
	case "node_updated":
		if ctrl, ok := i.controllerMap[payload.NodeID]; ok {
			ctrl.TriggerNodeSync()
		}

	case "subscriptions_updated":
		for _, ctrl := range i.controllerMap {
			ctrl.TriggerSubscriptionSync()
		}

	case "server_updated":
		// Trigger an immediate re-sync of the server's node list (server mode).
		if i.serverPollTrigger != nil {
			select {
			case i.serverPollTrigger <- struct{}{}:
			default:
			}
		}
	}
}

// drainReverbOutbound delivers queued push messages over the active Reverb connection.
func (i *Instance) drainReverbOutbound() {
	for ob := range i.reverbOutbound {
		i.mu.Lock()
		pusher := i.currentPusher
		i.mu.Unlock()

		if pusher != nil {
			ob.result <- pusher(ob.event, ob.data)
		} else {
			ob.result <- fmt.Errorf("no active Reverb connection")
		}
	}
}

// PushEvent sends an event to the panel via the active Reverb connection.
// Returns an error if there is no active connection.
func (i *Instance) PushEvent(event string, data any) error {
	result := make(chan error, 1)
	i.reverbOutbound <- reverbOutbound{event: event, data: data, result: result}
	return <-result
}

func awaitConnected(conn *websocket.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return "", err
		}
		var msg pusherMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.Event != "pusher:connection_established" {
			continue
		}
		var dataStr string
		if err := json.Unmarshal(msg.Data, &dataStr); err != nil {
			return "", fmt.Errorf("parse connection data: %w", err)
		}
		var connected pusherConnected
		if err := json.Unmarshal([]byte(dataStr), &connected); err != nil {
			return "", fmt.Errorf("parse socket_id: %w", err)
		}
		return connected.SocketID, nil
	}
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func signChannel(appKey, appSecret, socketID, channel string) string {
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(socketID + ":" + channel))
	return appKey + ":" + hex.EncodeToString(mac.Sum(nil))
}
