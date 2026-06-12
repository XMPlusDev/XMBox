package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/go-resty/resty/v2"
)

// GetSubscriptionList fetches the active subscription list for c.NodeID.
func (c *Client) GetSubscriptionList() (*[]SubscriptionInfo, error) {
	res, err := c.client.R().
		SetBody(map[string]string{"key": c.APIKey}).
		SetHeader("If-None-Match", c.eTags["subscriptions"]).
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		SetResult(&SubscriptionResponse{}).
		ForceContentType("application/json").
		Post("/api/server/subscription/lists/{serverId}")
	if err != nil {
		return nil, fmt.Errorf("GetSubscriptionList request: %w", err)
	}

	if res.StatusCode() == 304 {
		return nil, errors.New(SubscriptionNotModified)
	}
	if etag := res.Header().Get("Etag"); etag != "" && etag != c.eTags["subscriptions"] {
		c.eTags["subscriptions"] = etag
	}

	response, err := parseSubscriptionResponse(res, err)
	if err != nil {
		return nil, err
	}

	var raw []Subscription
	if err := json.Unmarshal(response.Data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", reflect.TypeOf(raw), err)
	}

	return parseSubscriptionList(&raw), nil
}

func parseSubscriptionResponse(res *resty.Response, err error) (*SubscriptionResponse, error) {
	if err != nil {
		return nil, fmt.Errorf("subscription request failed: %w", err)
	}
	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("subscription request error: %s", string(res.Body()))
	}
	resp, ok := res.Result().(*SubscriptionResponse)
	if !ok || resp == nil {
		return nil, fmt.Errorf("failed to parse subscription response")
	}
	return resp, nil
}

func parseSubscriptionList(raw *[]Subscription) *[]SubscriptionInfo {
	out := make([]SubscriptionInfo, 0, len(*raw))
	for _, s := range *raw {
		out = append(out, SubscriptionInfo{
			Id:           s.Id,
			UUID:         s.UUID,
			Passwd:       s.Passwd,
			Email:        s.Email,
			IPLimit:      s.Iplimit,
			SpeedLimit:   uint64(s.Speedlimit * 1000000 / 8),
		})
	}
	return &out
}

// ReportTraffic sends traffic counters to the panel.
func (c *Client) ReportTraffic(traffic *[]SubscriptionTraffic) error {
	data := make([]Traffic, len(*traffic))
	for i, t := range *traffic {
		data[i] = Traffic{Id: t.Id, Upload: t.Upload, Download: t.Download}
	}
	postData := &PostData{Key: c.APIKey, Data: data}

	res, err := c.client.R().
		SetBody(postData).
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		ForceContentType("application/json").
		Post("/api/server/subscription/traffic/{serverId}")
	if _, checkErr := c.checkResponse(res, err); checkErr != nil {
		return checkErr
	}
	return nil
}

// ReportOnlineIPs sends the currently connected IPs to the panel.
func (c *Client) ReportOnlineIPs(online *[]OnlineIP) error {
	c.access.Lock()
	defer c.access.Unlock()

	data := make([]AliveIP, len(*online))
	for i, ip := range *online {
		data[i] = AliveIP{Id: ip.Id, IP: ip.IP}
	}
	postData := &PostData{Key: c.APIKey, Data: data}

	res, err := c.client.R().
		SetBody(postData).
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post("/api/server/subscription/onlineip/{serverId}")
	if _, checkErr := c.checkResponse(res, err); checkErr != nil {
		return checkErr
	}
	return nil
}
