package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"errors"
	"strconv"
	"regexp"
    
	"github.com/bitly/go-simplejson"
)

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

	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["server"] {
		c.eTags["server"] = res.Header().Get("Etag")
	}

	response, err := c.checkResponse(res, err)
	if err != nil {
		return nil, err
	}

	b, _ := response.Encode()
	json.Unmarshal(b, server)

	if server.Protocol == "" {
		return nil, fmt.Errorf("Server protocol cannot be empty")
	}

	c.resp.Store(server)

	nodeInfo, err := c.NodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, error: %v", res.String(), err)
	}

	return nodeInfo, nil
}

func (c *Client) NodeResponse(s *serverConfig) (*NodeInfo, error) {
	nodeInfo := &NodeInfo{}
	
	nodeInfo.ID = c.NodeID
	nodeInfo.ServerKey = s.ServerKey
	nodeInfo.UpdateInterval = int(s.UpdateInterval)
	nodeInfo.Protocol = strings.ToLower(s.Protocol)
	nodeInfo.SpeedLimit = uint64(s.ServerSpeedlimit * 1000000 / 8)
	
	// network
	networkSettings, err := s.NetworkSettings.MarshalJSON()
	if err != nil {
		return nil, err
	}
	
	networkData, err := simplejson.NewJson(networkSettings)
	if err != nil {
		return nil, err
	}
	
	if err := c.parseNetworkSettings(networkData, nodeInfo); err != nil {
		return nil, err
	}
	
	// security
	security, err := s.SecuritySettings.MarshalJSON()
	if err != nil {
		return nil, err
	}

	securityData, err := simplejson.NewJson(security)
	if err != nil {
		return nil, err
	}
	
	if err := c.parseSecuritySettings(securityData, nodeInfo); err != nil {
		return nil, err
	}
	
	return nodeInfo, nil
}

func (c *Client) parseNetworkSettings(networkData *simplejson.Json, nodeInfo *NodeInfo) error {
	nodeInfo.NetworkSettings = &NetworkSettings{}
	
	networkIP, ipExist := networkData.CheckGet("listen_ip")
	if ipExist {
		nodeInfo.ListenAddr = networkIP.MustString()
	}
	
	networkPort, portExist := networkData.CheckGet("listen_port")
	if portExist {
		// Try int first, fall back to string
		if port, err := networkPort.Int(); err == nil {
			nodeInfo.ListenPort = uint16(port)
		} else if portStr, err := networkPort.String(); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				nodeInfo.ListenPort = uint16(port)
			}
		}
	}else{
		return fmt.Errorf("listening port is required")
	}
	networkTCPFastOpen, fastOpenExist := networkData.CheckGet("tcp_fast_open")
	if fastOpenExist {
		nodeInfo.TCPFastOpen = networkTCPFastOpen.MustBool()
	}
	
	networkCipher, cipherExist := networkData.CheckGet("cipher")
	if cipherExist {
		nodeInfo.NetworkSettings.Cipher = networkCipher.MustString()
	}
	
	transport, ok := networkData.CheckGet("transportProtocol")
	if !ok {
		return fmt.Errorf("Missing node transportProtocol configuration.")
	}
	transportType, typeExist := transport.CheckGet("type")
	if !typeExist {
		return fmt.Errorf("Missing node transportProtocol type.")
	}
	
	nodeInfo.NetworkSettings.Type = transportType.MustString()
	if nodeInfo.NetworkSettings.Type == "" {
		return fmt.Errorf("transportProtocol cannot be empty.")
	}
	
	transportSettings, settingsExist := transport.CheckGet("settings")
	if !settingsExist {
		return fmt.Errorf("Missing node transportProtocol settings.")
	}
	
	if nodeInfo.NetworkSettings.Type == "tcp" {
		if header, headerExist := transportSettings.CheckGet("header"); headerExist {
			if headerType, typeExist := header.CheckGet("type"); typeExist {
				nodeInfo.NetworkSettings.HeaderType = headerType.MustString()
			}
			if headerPath, pathExist := header.CheckGet("path"); pathExist {
				nodeInfo.NetworkSettings.Path = headerPath.MustString()
			}
			if headerHost, hostExist := header.CheckGet("host"); hostExist {
				nodeInfo.NetworkSettings.Host = headerHost.MustString()
				
				headers := make(map[string]string)
				headers["Host"] = headerHost.MustString()
				nodeInfo.NetworkSettings.Headers = headers
			}
			if headerMethod, methodExist := header.CheckGet("method");methodExist {
				nodeInfo.NetworkSettings.Method = headerMethod.MustString()
			}
		}
	}
	
	if nodeInfo.NetworkSettings.Type == "grpc" {
		networkServiceName, serviceNameExist := transportSettings.CheckGet("service_name")
		if serviceNameExist {
			nodeInfo.NetworkSettings.ServiceName = networkServiceName.MustString()
		}
	}
	
	if nodeInfo.NetworkSettings.Type == "httpupgrade" {
		if networkPath, pathExist := transportSettings.CheckGet("path"); pathExist {
			nodeInfo.NetworkSettings.Path = networkPath.MustString()
		}
		if headerHost, hostExist := transportSettings.CheckGet("host"); hostExist {
			nodeInfo.NetworkSettings.Host = headerHost.MustString()
		}
	}
	
	if nodeInfo.NetworkSettings.Type == "ws" {
		if networkPath, pathExist := transportSettings.CheckGet("path"); pathExist {
			nodeInfo.NetworkSettings.Path = networkPath.MustString()
		}
		networkEarlyData, earlydataExist := transportSettings.CheckGet("max_early_data")
		if earlydataExist {
			nodeInfo.NetworkSettings.MaxEarlyData = uint32(networkEarlyData.MustInt())
		}
	}
	
	// Hysteria
	ObfsType, obfsTypeExist := networkData.CheckGet("obfs_type")
	if obfsTypeExist {
		nodeInfo.NetworkSettings.ObfsType = ObfsType.MustString()
	}
	ObfsPasswd, obfsPassExist := networkData.CheckGet("obfs_password")
	if obfsPassExist {
		nodeInfo.NetworkSettings.ObfsPasswd = ObfsPasswd.MustString()
	}
	networkBBRProfile, profileExist := networkData.CheckGet("bbr_profile")
	if profileExist {
		nodeInfo.NetworkSettings.BBRProfile = networkBBRProfile.MustString()
	}
	networkIgnoreBandwidth, bandwidthExist := networkData.CheckGet("ignore_client_bandwidth")
	if bandwidthExist {
		nodeInfo.NetworkSettings.IgnoreClientBandwidth = networkIgnoreBandwidth.MustBool()
	}
	
	// Vless
	networkFlow, flowExist := networkData.CheckGet("flow")
	if flowExist {
		nodeInfo.NetworkSettings.Flow = networkFlow.MustString()
	}
	
	//TUIC
	networkCongestionControl, congestionExist := networkData.CheckGet("congestion_control")
	if congestionExist {
		nodeInfo.NetworkSettings.CongestionControl = networkCongestionControl.MustString()
	}
	
	//Naive
	networkQUICCongestionControl, controlExist := networkData.CheckGet("quic_congestion_control")
	if controlExist {
		nodeInfo.NetworkSettings.QUICCongestionControl = networkQUICCongestionControl.MustString()
	}
	
	// AnyTls
	if paddingArray, err := networkData.Get("padding_scheme").StringArray(); err == nil {
		nodeInfo.NetworkSettings.PaddingScheme = paddingArray
	}
	
	// ShadowTls
	shadowServer, shadowServerExist := networkData.CheckGet("handshake_server")
	if shadowServerExist {
		nodeInfo.NetworkSettings.HandshakeServer = shadowServer.MustString()
	}
	shadowServerPort, shadowServerPortExist := networkData.CheckGet("handshake_server_port")
	if shadowServerPortExist {
		nodeInfo.NetworkSettings.HandshakePort = uint16(shadowServerPort.MustInt())
	}
	strictMode, strictModeExist := networkData.CheckGet("strict_mode")
	if strictModeExist {
		nodeInfo.NetworkSettings.StrictMode = strictMode.MustBool()
	}
	
	return nil
}

func (c *Client) parseSecuritySettings(securityData *simplejson.Json, nodeInfo *NodeInfo) error {
	nodeInfo.TlsSettings = &TlsSettings{CertMode: "none"}
	nodeInfo.TlsSettings.Type = ""
	
	if tlsSettings, ok := securityData.CheckGet("tlsSettings"); ok {
		if tlsEnabled, ok := tlsSettings.CheckGet("enabled"); ok {
			nodeInfo.TlsSettings.Enabled = tlsEnabled.MustBool()
			if nodeInfo.TlsSettings.Enabled {
				nodeInfo.TlsSettings.Type = "tls"
			}
		}
		if certMode, ok := tlsSettings.CheckGet("cert_mode"); ok {
			nodeInfo.TlsSettings.CertMode = certMode.MustString()
		}
		//tls
		tlsServerName, ok := tlsSettings.CheckGet("server_name")
		if !ok {
			if nodeInfo.TlsSettings.Enabled {
				return fmt.Errorf("Invalid tls server name.")
			}
			// TLS disabled and no server_name — skip, leave ServerName empty
		} else {
			nodeInfo.TlsSettings.ServerName = tlsServerName.MustString()
		}
			
		if alpnArray, err := tlsSettings.Get("alpn").StringArray(); err == nil {
			nodeInfo.TlsSettings.Alpn = alpnArray
		}
		//tlsECH
		if tlsECH, ok := tlsSettings.CheckGet("ech"); ok {
			if echEnabled, ok := tlsECH.CheckGet("enabled"); ok {
				nodeInfo.TlsSettings.EnabledECH = echEnabled.MustBool()
			}
			if echArray, err := tlsECH.Get("key").StringArray(); err == nil {
				nodeInfo.TlsSettings.ECHKey = echArray
			}
		}
		// reality
		if tlsReality, ok := tlsSettings.CheckGet("reality"); ok {
			if realityEnabled, ok := tlsReality.CheckGet("enabled"); ok {
				nodeInfo.TlsSettings.RealityEnabled = realityEnabled.MustBool()
				if nodeInfo.TlsSettings.RealityEnabled {
					nodeInfo.TlsSettings.Type = "reality"
				}
			}
			if shortIdsArray, err := tlsReality.Get("short_ids").StringArray(); err == nil {
				nodeInfo.TlsSettings.RealityShortID = shortIdsArray
			}
			if privateKey, err := tlsReality.Get("private_key").String(); err == nil {
				nodeInfo.TlsSettings.RealityPrivateKey = privateKey
			}
			if serverName, ok := tlsReality.CheckGet("handshake_server"); ok {
				nodeInfo.TlsSettings.RealityServerName = serverName.MustString()
			}
			serverPort, ok := tlsReality.CheckGet("handshake_server_port")
			if ok {
				if port, err := serverPort.Int(); err == nil {
					nodeInfo.TlsSettings.RealityServerPort = uint16(port)
				} else if portStr, err := serverPort.String(); err == nil {
					if port, err := strconv.Atoi(portStr); err == nil {
						nodeInfo.TlsSettings.RealityServerPort = uint16(port)
					}
				}
			}else{
				if nodeInfo.TlsSettings.RealityEnabled && nodeInfo.TlsSettings.RealityServerPort < 1 {
				   return fmt.Errorf("reality server port is required")
				}
			}
		}
	}
	
	return nil
}

func (c *Client) GetNodeRule() (*[]DetectRules, error) {
	rules := new(ruleConfig)
	res, err := c.client.R().
		SetBody(map[string]string{"key": c.APIKey, "core": "singbox"}).
		ForceContentType("application/json").
		SetPathParam("serverId", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["rule"]).
		Post("/api/server/rules/{serverId}")
	if err != nil {
		return nil, err
	}
	if res.StatusCode() == 304 {
		return nil, errors.New(RuleNotModified)
	}
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["rule"] {
		c.eTags["rule"] = res.Header().Get("Etag")
	}
	response, err := c.checkResponse(res, err)
	if err != nil {
		return nil, err
	}
	b, _ := response.Encode()
	json.Unmarshal(b, rules)
	c.resp.Store(rules)

	ruleList := make([]DetectRules, 0, len(rules.RulesSettings))
	for i := range rules.RulesSettings {
		re, err := regexp.Compile(rules.RulesSettings[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex for rule %d %q: %w", rules.RulesSettings[i].Id, rules.RulesSettings[i].Regex, err)
		}
		ruleList = append(ruleList, DetectRules{
			ID:      rules.RulesSettings[i].Id,
			Pattern: re,
		})
	}
	return &ruleList, nil
}