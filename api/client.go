package api

import (
	"log"
	"sync/atomic"
	"time"
	"sync"
	"fmt"
	"strings"
	
	"github.com/go-resty/resty/v2"
	"github.com/bitly/go-simplejson"
)

type Client struct {
	client           *resty.Client
	APIHost          string
	NodeID           int
	APIKey           string
	resp             atomic.Value
	eTags            map[string]string
	access           sync.Mutex
}

type ClientInfo struct {
	APIHost string
	NodeID  int
	APIKey   string
}

func New(apiConfig *Config) *Client {
	if !strings.HasPrefix(apiConfig.APIHost, "https://") {
		log.Fatalf("ERROR: APIHost must use HTTPS protocol. Got: %s (expected format: https://tld.com or https://xx.tld.com)", apiConfig.APIHost)
	}

	client := resty.New()
	client.SetRetryCount(5)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			log.Print(v.Err)
		}
	})
	
	client.SetBaseURL(apiConfig.APIHost)
	
	apiClient := &Client{
		client:           client,
		NodeID:           apiConfig.NodeID,
		APIKey:           apiConfig.APIKey,
		APIHost:          apiConfig.APIHost,
		eTags:            make(map[string]string),
	}
	
	return apiClient
}

func (c *Client) Describe() ClientInfo {
	return ClientInfo{
		APIHost: c.APIHost,
		NodeID:  c.NodeID,
		APIKey:  c.APIKey,
	}
}

func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) checkResponse(res *resty.Response, err error) (*simplejson.Json, error) {
	if err != nil {
		var requestURL string
		if res != nil && res.Request != nil && res.Request.RawRequest != nil {
			requestURL = res.Request.RawRequest.URL.String()
		}
		return nil, fmt.Errorf("request error occurred for URL %s: %s", requestURL, err)
	}

	if res.StatusCode() >= 400 {
		requestURL := "unknown"
		if res.Request != nil && res.Request.RawRequest != nil {
			requestURL = res.Request.RawRequest.URL.String()
		}
		return nil, fmt.Errorf("request %s failed: %s", requestURL, string(res.Body()))
	}

	result, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %s", res.String())
	}

	return result, nil
}