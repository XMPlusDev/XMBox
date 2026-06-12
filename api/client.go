package api

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
)

// Client is the HTTP client for the panel API.
type Client struct {
	client   *resty.Client
	APIHost  string
	NodeID   int
	ServerID int // machine-level ID; >0 means server mode
	APIKey   string
	resp     atomic.Value
	eTags    map[string]string
	access   sync.Mutex
}

// ClientInfo is a lightweight, loggable snapshot of the client's identity.
type ClientInfo struct {
	APIHost  string
	NodeID   int
	ServerID int
	APIKey   string
}

// New creates an API Client from a Config.
func New(apiConfig *Config) *Client {
	if !strings.HasPrefix(apiConfig.APIHost, "https://") {
		log.Fatalf("ERROR: APIHost must use HTTPS. Got: %s", apiConfig.APIHost)
	}

	r := resty.New()
	r.SetRetryCount(5)
	timeout := 30 * time.Second
	if apiConfig.Timeout > 0 {
		timeout = time.Duration(apiConfig.Timeout) * time.Second
	}
	r.SetTimeout(timeout)
	r.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			log.Print(v.Err)
		}
	})
	r.SetBaseURL(apiConfig.APIHost)

	return &Client{
		client:   r,
		NodeID:   apiConfig.NodeID,
		ServerID: apiConfig.ServerID,
		APIKey:   apiConfig.APIKey,
		APIHost:  apiConfig.APIHost,
		eTags:    make(map[string]string),
	}
}

// ForNode returns a new Client configured for the given node ID, sharing
// the same underlying HTTP client and credentials.
func (c *Client) ForNode(nodeID int) *Client {
	clone := &Client{
		client:   c.client,
		APIHost:  c.APIHost,
		NodeID:   nodeID,
		ServerID: c.ServerID,
		APIKey:   c.APIKey,
		eTags:    make(map[string]string),
	}
	return clone
}

// Describe returns a lightweight snapshot of this client's identity.
func (c *Client) Describe() ClientInfo {
	return ClientInfo{
		APIHost:  c.APIHost,
		NodeID:   c.NodeID,
		ServerID: c.ServerID,
		APIKey:   c.APIKey,
	}
}

// Debug enables resty request/response logging.
func (c *Client) Debug() { c.client.SetDebug(true) }

// checkResponse validates an HTTP response and returns the parsed JSON body.
func (c *Client) checkResponse(res *resty.Response, err error) (*simplejson.Json, error) {
	if err != nil {
		url := ""
		if res != nil && res.Request != nil && res.Request.RawRequest != nil {
			url = res.Request.RawRequest.URL.String()
		}
		return nil, fmt.Errorf("request error %s: %w", url, err)
	}
	if res.StatusCode() >= 400 {
		url := "unknown"
		if res.Request != nil && res.Request.RawRequest != nil {
			url = res.Request.RawRequest.URL.String()
		}
		return nil, fmt.Errorf("request %s failed: %s", url, string(res.Body()))
	}
	result, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("parse JSON response: %s", res.String())
	}
	return result, nil
}
