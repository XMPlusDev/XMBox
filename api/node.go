package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"math/rand"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
)

// GetServerNodes fetches the list of node IDs assigned to this machine (server mode).
func (c *Client) GetServerNodes() (*ServerNodesResponse, error) {
	res, err := c.client.R().
		SetBody(map[string]string{"key": c.APIKey, "core": "singbox"}).
		ForceContentType("application/json").
		SetPathParam("machineId", strconv.Itoa(c.ServerID)).
		Post("/api/server/nodes/{machineId}")
	if err != nil {
		return nil, fmt.Errorf("GetServerNodes request: %w", err)
	}
	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("GetServerNodes error: %s", string(res.Body()))
	}

	result, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("parse GetServerNodes response: %w", err)
	}

	raw, _ := result.Encode()
	var resp ServerNodesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal ServerNodesResponse: %w", err)
	}
	if resp.PollInterval <= 0 {
		resp.PollInterval = 60
	}
	return &resp, nil
}

// ReportServerStatus sends machine health metrics to the panel.
// serverID is the machine ID (not the node ID).
func (c *Client) ReportServerStatus(serverID int, status *ServerStatus) error {
	postData := &PostData{Key: c.APIKey, Data: status}

	res, err := c.client.R().
		SetBody(postData).
		SetPathParam("machineId", strconv.Itoa(serverID)).
		ForceContentType("application/json").
		Post("/api/server/status/{machineId}")
	if _, checkErr := c.checkResponse(res, err); checkErr != nil {
		return checkErr
	}
	return nil
}

// GetNodeInfo fetches and parses the configuration for c.NodeID.
func (c *Client) GetNodeInfo() (*NodeInfo, error) {
	server := new(serverConfig)

	res, err := c.client.R().
		SetBody(map[string]string{"key": c.APIKey, "core": "singbox"}).
		ForceContentType("application/json").
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["server"]).
		Post("/api/server/info/{serverId}")
	if err != nil {
		return nil, err
	}

	if res.StatusCode() == 304 {
		return nil, errors.New(NodeNotModified)
	}
	if etag := res.Header().Get("Etag"); etag != "" && etag != c.eTags["server"] {
		c.eTags["server"] = etag
	}

	response, err := c.checkResponse(res, err)
	if err != nil {
		return nil, err
	}

	b, _ := response.Encode()
	if err := json.Unmarshal(b, server); err != nil {
		return nil, fmt.Errorf("unmarshal serverConfig: %w", err)
	}

	if server.Protocol == "" {
		return nil, fmt.Errorf("server protocol is empty")
	}
	if server.Version < 2605130 {
		return nil, fmt.Errorf("panel version too old (v%d); please update to v2605130+", server.Version)
	}

	c.resp.Store(server)

	nodeInfo, err := c.NodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("parse node info: %w (raw: %s)", err, res.String())
	}
	return nodeInfo, nil
}

// NodeResponse converts a raw serverConfig into a NodeInfo.
func (c *Client) NodeResponse(s *serverConfig) (*NodeInfo, error) {
	nodeInfo := &NodeInfo{
		ID:             c.NodeID,
		ServerKey:      s.ServerKey,
		UpdateInterval: int(s.UpdateInterval),
		Protocol:       strings.ToLower(s.Protocol),
		SpeedLimit:     uint64(s.ServerSpeedlimit * 1000000 / 8),
		RelayType:      s.RelayType,
		RelayNodeID:    s.RelayNodeId,
		IgnoreIPs:      s.IgnoreIPs,
	}

	// Network settings
	netJSON, err := s.NetworkSettings.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal NetworkSettings: %w", err)
	}
	netData, err := simplejson.NewJson(netJSON)
	if err != nil {
		return nil, fmt.Errorf("parse NetworkSettings JSON: %w", err)
	}
	if err := c.parseNetworkSettings(netData, nodeInfo); err != nil {
		return nil, err
	}

	// Security settings
	secJSON, err := s.SecuritySettings.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal SecuritySettings: %w", err)
	}
	secData, err := simplejson.NewJson(secJSON)
	if err != nil {
		return nil, fmt.Errorf("parse SecuritySettings JSON: %w", err)
	}
	if err := c.parseSecuritySettings(secData, nodeInfo); err != nil {
		return nil, err
	}

	// FallbackConfig — only parsed for trojan and vless
	proto := strings.ToLower(s.Protocol)
	if proto == "trojan" {
		if fallback, err := c.parseFallbackConfig(netData); err == nil && fallback != nil {
			nodeInfo.FallbackConfig = fallback
		}
	}

	return nodeInfo, nil
}

// parseFallbackConfig reads the optional "fallback" object from network settings.
// The panel sends a single object with "server" and "server_port" fields.
func (c *Client) parseFallbackConfig(networkData *simplejson.Json) (*FallbackConfig, error) {
	fallbackJSON, ok := networkData.CheckGet("fallback")
	if !ok {
		return nil, nil
	}

	raw, err := fallbackJSON.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var f FallbackConfig
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("unmarshal fallback: %w", err)
	}
	if f.Server == "" || f.ServerPort == 0 {
		return nil, nil // incomplete fallback — ignore
	}
	return &f, nil
}

func (c *Client) parseNetworkSettings(networkData *simplejson.Json, nodeInfo *NodeInfo) error {
	nodeInfo.NetworkSettings = &NetworkSettings{}

	if ip, ok := networkData.CheckGet("listen_ip"); ok {
		nodeInfo.ListenAddr = ip.MustString()
	}

	portNode, ok := networkData.CheckGet("listen_port")
	if !ok {
		return fmt.Errorf("listen_port is required")
	}
	if port, err := portNode.Int(); err == nil {
		nodeInfo.ListenPort = uint16(port)
	} else if s, err := portNode.String(); err == nil {
		if p, err := strconv.Atoi(s); err == nil {
			nodeInfo.ListenPort = uint16(p)
		}
	}

	if tfo, ok := networkData.CheckGet("tcp_fast_open"); ok {
		nodeInfo.TCPFastOpen = tfo.MustBool()
	}
	if cipher, ok := networkData.CheckGet("cipher"); ok {
		nodeInfo.NetworkSettings.Cipher = cipher.MustString()
	}

	transport, ok := networkData.CheckGet("transportProtocol")
	if !ok {
		return fmt.Errorf("missing transportProtocol")
	}
	typeNode, ok := transport.CheckGet("type")
	if !ok {
		return fmt.Errorf("missing transportProtocol.type")
	}
	nodeInfo.NetworkSettings.Type = typeNode.MustString()
	if nodeInfo.NetworkSettings.Type == "" {
		return fmt.Errorf("transportProtocol.type is empty")
	}

	settings, ok := transport.CheckGet("settings")
	if !ok {
		return fmt.Errorf("missing transportProtocol.settings")
	}

	// ShadowTLS is declared as a plug-in on the transport. Only tcp can carry
	// it: a fronted node's connections arrive by injection through a detour,
	// which bypasses the transport layer, so ws, grpc and httpupgrade would be
	// spoken by the client and never read by the server.
	if plugin, ok := transport.CheckGet("plug-in"); ok {
		name, _ := plugin.CheckGet("name")
		if name != nil && strings.EqualFold(name.MustString(), "shadowtls") {
			if nodeInfo.NetworkSettings.Type != "tcp" {
				return fmt.Errorf("shadowtls plug-in needs transportProtocol.type tcp, got %q", nodeInfo.NetworkSettings.Type)
			}
			nodeInfo.NetworkSettings.ShadowTLS = parseShadowTLSSettings(plugin)
		}
	}

	switch nodeInfo.NetworkSettings.Type {
	case "tcp":
		if header, ok := settings.CheckGet("header"); ok {
			if t, ok := header.CheckGet("type"); ok {
				nodeInfo.NetworkSettings.HeaderType = t.MustString()
			}
			if p, ok := header.CheckGet("path"); ok {
				nodeInfo.NetworkSettings.Path = p.MustString()
			}
			if h, ok := header.CheckGet("host"); ok {
				nodeInfo.NetworkSettings.Host = h.MustString()
				nodeInfo.NetworkSettings.Headers = map[string]string{"Host": h.MustString()}
			}
			if m, ok := header.CheckGet("method"); ok {
				nodeInfo.NetworkSettings.Method = m.MustString()
			}
		}
	case "grpc":
		if sn, ok := settings.CheckGet("service_name"); ok {
			nodeInfo.NetworkSettings.ServiceName = sn.MustString()
		}
	case "httpupgrade":
		if p, ok := settings.CheckGet("path"); ok {
			nodeInfo.NetworkSettings.Path = p.MustString()
		}
		if h, ok := settings.CheckGet("host"); ok {
			nodeInfo.NetworkSettings.Host = h.MustString()
		}
	case "ws":
		if p, ok := settings.CheckGet("path"); ok {
			nodeInfo.NetworkSettings.Path = p.MustString()
		}
		if ed, ok := settings.CheckGet("max_early_data"); ok {
			nodeInfo.NetworkSettings.MaxEarlyData = uint32(ed.MustInt())
		}
	}

	// Hysteria 2
	if v, ok := networkData.CheckGet("obfs_type"); ok {
		nodeInfo.NetworkSettings.ObfsType = v.MustString()
	}
	if v, ok := networkData.CheckGet("obfs_password"); ok {
		nodeInfo.NetworkSettings.ObfsPasswd = v.MustString()
	}
	if v, ok := networkData.CheckGet("bbr_profile"); ok {
		nodeInfo.NetworkSettings.BBRProfile = v.MustString()
	}
	if v, ok := networkData.CheckGet("ignore_client_bandwidth"); ok {
		nodeInfo.NetworkSettings.IgnoreClientBandwidth = v.MustBool()
	}
	if v, ok := networkData.CheckGet("realm_server_url"); ok {
		nodeInfo.NetworkSettings.RealmServerURL = v.MustString()
	}
	if v, ok := networkData.CheckGet("realm_token"); ok {
		nodeInfo.NetworkSettings.RealmToken = v.MustString()
	}
	if v, ok := networkData.CheckGet("realm_id"); ok {
		nodeInfo.NetworkSettings.RealmID = v.MustString()
	}
	if a, err := networkData.Get("realm_stun_servers").StringArray(); err == nil {
		nodeInfo.NetworkSettings.RealmSTUNServers = a
	}
	if v, err := networkData.Get("geckoMinPacketSize").Int(); err == nil {
		nodeInfo.NetworkSettings.GeckoMinPacketSize = v
	}
	if v, err := networkData.Get("geckoMaxPacketSize").Int(); err == nil {
		nodeInfo.NetworkSettings.GeckoMaxPacketSize = v
	}

	// VLESS flow
	if v, ok := networkData.CheckGet("flow"); ok {
		nodeInfo.NetworkSettings.Flow = v.MustString()
	}

	// TUIC
	if v, ok := networkData.CheckGet("congestion_control"); ok {
		nodeInfo.NetworkSettings.CongestionControl = v.MustString()
	}

	// Naive
	if v, ok := networkData.CheckGet("quic_congestion_control"); ok {
		nodeInfo.NetworkSettings.QUICCongestionControl = v.MustString()
	}

	// AnyTLS
	if a, err := networkData.Get("padding_scheme").StringArray(); err == nil {
		nodeInfo.NetworkSettings.PaddingScheme = a
	}

	return nil
}

// parseShadowTLSSettings reads the ShadowTLS plug-in block. That plug-in is the
// only way ShadowTLS is enabled — there is no top-level switch and no protocol
// named after it — so a node either declares it on its tcp transport or is not
// fronted at all.
func parseShadowTLSSettings(data *simplejson.Json) *ShadowTLSSettings {
	settings := &ShadowTLSSettings{Version: 3}
	if v, ok := data.CheckGet("version"); ok {
		if version := v.MustInt(); version != 0 {
			settings.Version = version
		}
	}
	if v, ok := data.CheckGet("handshake_server"); ok {
		settings.HandshakeServer = v.MustString()
	}
	if v, ok := data.CheckGet("handshake_server_port"); ok {
		settings.HandshakePort = uint16(v.MustInt())
	}
	if v, ok := data.CheckGet("strict_mode"); ok {
		settings.StrictMode = v.MustBool()
	}
	if v, ok := data.CheckGet("wildcard_sni"); ok {
		settings.WildcardSNI = v.MustString()
	}
	return settings
}

func (c *Client) parseSecuritySettings(securityData *simplejson.Json, nodeInfo *NodeInfo) error {
	nodeInfo.TlsSettings = &TlsSettings{CertMode: "none"}

	tlsNode, ok := securityData.CheckGet("tlsSettings")
	if !ok {
		return nil
	}

	if enabled, ok := tlsNode.CheckGet("enabled"); ok {
		nodeInfo.TlsSettings.Enabled = enabled.MustBool()
		if nodeInfo.TlsSettings.Enabled {
			nodeInfo.TlsSettings.Type = "tls"
		}
	}
	if cm, ok := tlsNode.CheckGet("cert_mode"); ok {
		nodeInfo.TlsSettings.CertMode = cm.MustString()
	}
	if certDomain, ok := tlsNode.CheckGet("cert_domain_name"); ok {
		if name, err := certDomain.String(); err == nil {
			nodeInfo.TlsSettings.CertDomainName = name
		} else if nodeInfo.TlsSettings.CertMode != "none" {
			return fmt.Errorf("certificate domain name is required")
		}
	} else {
		return fmt.Errorf("certDomainName key missing from tlsSettings")
	}
	if certEmail, ok := tlsNode.CheckGet("cert_email"); ok {
		if email, err := certEmail.String(); err == nil {
			nodeInfo.TlsSettings.CertEmail = email
		}
	}
	if v, err := tlsNode.Get("dns_provider").String(); err == nil {
		nodeInfo.TlsSettings.DnsProvider = v
	}
	if v, err := tlsNode.Get("cert_file").String(); err == nil {
		nodeInfo.TlsSettings.CertFile = v
	}
	if v, err := tlsNode.Get("key_file").String(); err == nil {
		nodeInfo.TlsSettings.KeyFile = v
	}
	if sn, ok := tlsNode.CheckGet("server_name"); ok {
		nodeInfo.TlsSettings.ServerName = sn.MustString()
	} else if nodeInfo.TlsSettings.Enabled {
		return fmt.Errorf("TLS is enabled but server_name is missing")
	}
	if alpn, err := tlsNode.Get("alpn").StringArray(); err == nil {
		nodeInfo.TlsSettings.Alpn = alpn
	}

	// ECH
	if ech, ok := tlsNode.CheckGet("ech"); ok {
		if v, ok := ech.CheckGet("enabled"); ok {
			nodeInfo.TlsSettings.EnabledECH = v.MustBool()
		}
		if keys, err := ech.Get("key").StringArray(); err == nil {
			nodeInfo.TlsSettings.ECHKey = keys
		}
	}

	// Reality
	if reality, ok := tlsNode.CheckGet("reality"); ok {
		if v, ok := reality.CheckGet("enabled"); ok {
			nodeInfo.TlsSettings.RealityEnabled = v.MustBool()
			if nodeInfo.TlsSettings.RealityEnabled {
				nodeInfo.TlsSettings.Type = "reality"
			}
		}
		if ids, err := reality.Get("short_ids").StringArray(); err == nil {
			nodeInfo.TlsSettings.RealityShortID = ids
		}
		if pk, err := reality.Get("private_key").String(); err == nil {
			nodeInfo.TlsSettings.RealityPrivateKey = pk
		}
		if sn, ok := reality.CheckGet("handshake_server"); ok {
			nodeInfo.TlsSettings.RealityServerName = sn.MustString()
		}
		if portNode, ok := reality.CheckGet("handshake_server_port"); ok {
			if p, err := portNode.Int(); err == nil {
				nodeInfo.TlsSettings.RealityServerPort = uint16(p)
			} else if s, err := portNode.String(); err == nil {
				if p, err := strconv.Atoi(s); err == nil {
					nodeInfo.TlsSettings.RealityServerPort = uint16(p)
				}
			}
		}
		if nodeInfo.TlsSettings.RealityEnabled && nodeInfo.TlsSettings.RealityServerPort == 0 {
			return fmt.Errorf("reality handshake_server_port is required")
		}
	}

	return nil
}

// GetTransitNode builds a RelayNodeInfo from the transit_server section of
// the most recently fetched serverConfig (cached by GetNodeInfo).
func (c *Client) GetTransitNode() (*RelayNodeInfo, error) {
	cached := c.resp.Load()
	if cached == nil {
		return nil, fmt.Errorf("node info not loaded yet")
	}
	s, ok := cached.(*serverConfig)
	if !ok {
		return nil, fmt.Errorf("unexpected cached server config type")
	}
	if s.RType == "" {
		return nil, fmt.Errorf("no transit server configured")
	}

	nodeInfo := &RelayNodeInfo{
		NodeType:  strings.ToLower(s.RType),
		Address:   s.RAddress,
		ServerKey: s.RServerKey,
	}
	
	connectPort, err := selectSinglePort(s.RPort)
	if err != nil {
		return nil, fmt.Errorf("failed to parse relay connection port: %w", err)
	}
	nodeInfo.Port = uint16(connectPort)

	// Network settings
	netJSON, err := s.RNetworkSettings.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal RNetworkSettings: %w", err)
	}
	netData, err := simplejson.NewJson(netJSON)
	if err != nil {
		return nil, fmt.Errorf("parse RNetworkSettings JSON: %w", err)
	}
	if err := c.parseRelayNetworkSettings(netData, nodeInfo); err != nil {
		return nil, err
	}

	// Security settings
	secJSON, err := s.RSecuritySettings.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal RSecuritySettings: %w", err)
	}
	secData, err := simplejson.NewJson(secJSON)
	if err != nil {
		return nil, fmt.Errorf("parse RSecuritySettings JSON: %w", err)
	}
	if err := c.parseRelaySecuritySettings(secData, nodeInfo); err != nil {
		return nil, err
	}

	return nodeInfo, nil
}

// parseRelayNetworkSettings parses the transit node's transport settings into
// nodeInfo.Port and nodeInfo.NetworkSettings, reusing the same wire format as
// parseNetworkSettings.
func (c *Client) parseRelayNetworkSettings(networkData *simplejson.Json, nodeInfo *RelayNodeInfo) error {
	/*portNode, ok := networkData.CheckGet("listen_port")
	if !ok {
		return fmt.Errorf("listen_port is required")
	}
	if port, err := portNode.Int(); err == nil {
		nodeInfo.Port = uint16(port)
	} else if str, err := portNode.String(); err == nil {
		if p, err := strconv.Atoi(str); err == nil {
			nodeInfo.Port = uint16(p)
		}
	}*/

	if cipher, ok := networkData.CheckGet("cipher"); ok {
		nodeInfo.Cipher = cipher.MustString()
	}

	// Reuse the regular NodeInfo network-settings parser for transport-level
	// fields (transportProtocol, ws/grpc/httpupgrade options, hysteria2,
	// tuic, shadowtls, anytls, naive, etc.).
	tmp := &NodeInfo{}
	if err := c.parseNetworkSettings(networkData, tmp); err != nil {
		return err
	}
	nodeInfo.NetworkSettings = tmp.NetworkSettings

	if nodeInfo.NodeType == "vless" {
		if v, ok := networkData.CheckGet("flow"); ok {
			nodeInfo.Flow = v.MustString()
		}
	}

	return nil
}

// parseRelaySecuritySettings parses the transit node's security settings
// (TLS/Reality) into nodeInfo.TlsSettings.
func (c *Client) parseRelaySecuritySettings(securityData *simplejson.Json, nodeInfo *RelayNodeInfo) error {
	tls := &TlsSettings{}

	if tlsNode, ok := securityData.CheckGet("tlsSettings"); ok {
		if enabled, ok := tlsNode.CheckGet("enabled"); ok {
			tls.Enabled = enabled.MustBool()
			if tls.Enabled {
				tls.Type = "tls"
			}
		}
		if sn, ok := tlsNode.CheckGet("server_name"); ok {
			tls.ServerName = sn.MustString()
		}
		if alpn, err := tlsNode.Get("alpn").StringArray(); err == nil {
			tls.Alpn = alpn
		}
	}

	if realityNode, ok := securityData.CheckGet("realitySettings"); ok {
		if v, ok := realityNode.CheckGet("enabled"); ok {
			tls.RealityEnabled = v.MustBool()
			if tls.RealityEnabled {
				tls.Enabled = true
				tls.Type = "reality"
			}
		}
		if sn, ok := realityNode.CheckGet("server_name"); ok {
			tls.ServerName = sn.MustString()
		}
		if ids, err := realityNode.Get("short_ids").StringArray(); err == nil {
			tls.RealityShortID = ids
		}
	}

	if tls.Enabled {
		nodeInfo.TlsSettings = tls
	}

	return nil
}

// GetNodeRule fetches the blocking rules for c.NodeID.
func (c *Client) GetNodeRule() (*[]DetectRules, error) {
	res, err := c.client.R().
		SetBody(map[string]string{"key": c.APIKey, "core": "singbox"}).
		ForceContentType("application/json").
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["rule"]).
		SetResult(&RuleResponse{}).
		Post("/api/server/rules/{serverId}")
	if err != nil {
		return nil, err
	}

	if res.StatusCode() == 304 {
		return nil, errors.New(RuleNotModified)
	}
	if etag := res.Header().Get("ETag"); etag != "" {
		if etag == c.eTags["rule"] {
			return nil, errors.New(RuleNotModified)
		}
		c.eTags["rule"] = etag
	}

	response, err := parseRuleResponse(res, err)
	if err != nil {
		return nil, err
	}

	var rulesList []Rule
	if err := json.Unmarshal(response.Data, &rulesList); err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}
	return parseRulesList(&rulesList)
}

func parseRuleResponse(res *resty.Response, err error) (*RuleResponse, error) {
	if err != nil {
		return nil, fmt.Errorf("rule request failed: %w", err)
	}
	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("rule request error: %s", string(res.Body()))
	}
	response, ok := res.Result().(*RuleResponse)
	if !ok || response == nil {
		return nil, fmt.Errorf("failed to parse rule response")
	}
	return response, nil
}

func parseRulesList(rules *[]Rule) (*[]DetectRules, error) {
	out := make([]DetectRules, 0, len(*rules))
	for _, r := range *rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex for rule %d %q: %w", r.Id, r.Regex, err)
		}
		out = append(out, DetectRules{ID: r.Id, Pattern: re})
	}
	return &out, nil
}

func selectSinglePort(portString string) (uint32, error) {
	if portString == "" {
		return 0, fmt.Errorf("port string is empty")
	}

	var allPorts []uint32

	if strings.Contains(portString, ",") {
		for _, p := range strings.Split(portString, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			ports, err := expandPortRange(p)
			if err != nil {
				return 0, err
			}
			allPorts = append(allPorts, ports...)
		}
	} else if strings.Contains(portString, "-") {
		ports, err := expandPortRange(portString)
		if err != nil {
			return 0, err
		}
		allPorts = append(allPorts, ports...)
	} else {
		port, err := strconv.ParseUint(portString, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid port number: %s", portString)
		}
		if port < 1 || port > 65535 {
			return 0, fmt.Errorf("port out of range: %d", port)
		}
		return uint32(port), nil
	}

	if len(allPorts) == 0 {
		return 0, fmt.Errorf("no valid ports found in: %s", portString)
	}
	return allPorts[rand.Intn(len(allPorts))], nil
}

func expandPortRange(p string) ([]uint32, error) {
	if strings.Contains(p, "-") {
		parts := strings.SplitN(p, "-", 2)
		from, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid port in range: %s", parts[0])
		}
		to, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid port in range: %s", parts[1])
		}
		if from < 1 || from > 65535 || to < 1 || to > 65535 {
			return nil, fmt.Errorf("port out of range: %d-%d", from, to)
		}
		var ports []uint32
		for i := from; i <= to; i++ {
			ports = append(ports, uint32(i))
		}
		return ports, nil
	}
	port, err := strconv.ParseUint(p, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %s", p)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	return []uint32{uint32(port)}, nil
}