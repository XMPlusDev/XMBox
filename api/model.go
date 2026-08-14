package api

import (
	"encoding/json"
	"regexp"
)

const (
	SubscriptionNotModified = "subscriptions_not_modified"
	NodeNotModified         = "node_not_modified"
	RuleNotModified         = "rules_not_modified"
)

// Config holds the API connection parameters for a node or machine.
type Config struct {
	APIHost  string `mapstructure:"ApiHost"`
	NodeID   int    `mapstructure:"NodeID"`
	ServerID int    `mapstructure:"ServerID"` // machine-level ID; >0 activates server mode
	APIKey   string `mapstructure:"ApiKey"`
	Timeout  int    `mapstructure:"Timeout"`
}

// Response is the generic panel API envelope.
type Response struct {
	Data json.RawMessage `json:"data"`
}

// PostData is the standard POST body wrapper.
type PostData struct {
	Key  string      `json:"key"`
	Data interface{} `json:"data"`
}

// serverConfig is the raw response from /api/server/info/{id}.
type serverConfig struct {
	server         `json:"server"`
	transitServer `json:"transit_server"`
	UpdateInterval int `json:"update_interval"`
	Version        int `json:"api_version"`
	IgnoreIPs      []string `json:"ignore_ips"`
}

type server struct {
	Protocol         string           `json:"type"`
	RelayNodeId      int              `json:"transit_server_id"`
	RelayType        int              `json:"transit_server_type"`
	ServerSpeedlimit int              `json:"speed_limit"`
	ServerKey        string           `json:"server_key"`
	Addr             string           `json:"address"`
	IP               string           `json:"ip"`
	NetworkSettings  *json.RawMessage `json:"transportSettings"`
	SecuritySettings *json.RawMessage `json:"securitySettings"`
}

type transitServer struct {
	RType             string           `json:"type"`
	NodeId            int              `json:"server_id"`
	RAddress          string           `json:"address"`
	RPort             string           `json:"server_port"`
	RServerKey        string           `json:"server_key"`
	RNetworkSettings  *json.RawMessage `json:"transportSettings"`
	RSecuritySettings *json.RawMessage `json:"securitySettings"`
}

// RuleResponse is the envelope for /api/server/rules/{id}.
type RuleResponse struct {
	Data json.RawMessage `json:"ruleSettings"`
}

// Rule is a single raw blocking rule from the panel.
type Rule struct {
	Id    int    `json:"id"`
	Regex string `json:"value"`
}

// DetectRules is a compiled blocking rule.
type DetectRules struct {
	ID      int
	Pattern *regexp.Regexp
}

// SubscriptionResponse is the envelope for /api/server/subscription/lists/{id}.
type SubscriptionResponse struct {
	Data json.RawMessage `json:"subscriptions"`
}

// Subscription is the raw subscription record from the panel.
type Subscription struct {
	Id           int    `json:"id"`
	UUID         string `json:"uuid"`
	Passwd       string `json:"passwd"`
	Email        string `json:"email"`
	Speedlimit   int    `json:"speed_limit"`
	Iplimit      int    `json:"ip_limit"`
}

// NetworkSettings holds parsed transport-layer settings.
type NetworkSettings struct {
	Type string

	// Shadowsocks
	Cipher string

	// WebSocket / HTTP / HTTPUpgrade
	Path      string
	Host      string
	Method    string
	HeaderType string
	Headers    map[string]string

	MaxEarlyData uint32

	// gRPC
	ServiceName string

	// Hysteria 2
	ObfsType              string
	ObfsPasswd            string
	GeckoMinPacketSize    int
	GeckoMaxPacketSize    int
	BBRProfile            string
	IgnoreClientBandwidth bool
	RealmServerURL        string
	RealmToken            string
	RealmID               string
	RealmSTUNServers      []string

	// TUIC
	CongestionControl string

	// VLESS
	Flow string

	// ShadowTLS
	HandshakeServer string
	HandshakePort   uint16
	StrictMode      bool
	// WildcardSNI is "off", "authed", or "all". When not "off" the handshake
	// target becomes the client's own SNI on port 443 instead of
	// HandshakeServer, so each client picks the site it impersonates.
	WildcardSNI string

	// AnyTLS
	PaddingScheme []string

	// Naive
	QUICCongestionControl string
}

// TlsSettings holds TLS and Reality configuration.
type TlsSettings struct {
	Type     string
	Enabled  bool
	CertMode string
	CertDomainName string
	CertEmail  string
	ServerName string
	Alpn       []string
	EnabledECH bool
	ECHKey     []string

	RealityEnabled    bool
	RealityPrivateKey string
	RealityShortID    []string
	RealityServerName string
	RealityServerPort uint16

	DnsProvider string
	CertFile    string
	KeyFile     string
}

// FallbackConfig describes a single inbound fallback destination.
// Only used for trojan (and optionally vless) protocol nodes.
type FallbackConfig struct {
	Server     string 
	ServerPort uint16 
}

// NodeInfo is the parsed node configuration returned by GetNodeInfo.
type NodeInfo struct {
	ID              int
	ServerKey       string
	IgnoreIPs       []string
	Protocol        string
	SpeedLimit      uint64
	UpdateInterval  int
	ListenAddr      string
	ListenPort      uint16
	TCPFastOpen     bool
	TlsSettings     *TlsSettings
	NetworkSettings *NetworkSettings
	FallbackConfig *FallbackConfig
	RelayType   int
	RelayNodeID int
}

// RelayNodeInfo describes a downstream relay target that per-subscription
// outbounds are built towards (sing-box analog of xray-core's RelayNodeInfo).
type RelayNodeInfo struct {
	NodeType        string
	Address         string
	Port            uint16
	ServerKey       string
	Cipher          string
	Flow            string
	NetworkSettings *NetworkSettings
	TlsSettings     *TlsSettings
}

// SubscriptionInfo is the parsed per-user record used by the controller.
type SubscriptionInfo struct {
	Id           int
	UUID         string
	Passwd       string
	Email        string
	SpeedLimit   uint64
	IPLimit      int
}

// OnlineIP represents a currently connected IP address for a subscription.
type OnlineIP struct {
	Id int
	IP string
}

// SubscriptionTraffic holds accumulated traffic counters for one subscription.
type SubscriptionTraffic struct {
	Id       int
	Upload   int64
	Download int64
}

// Traffic is the wire format for ReportTraffic.
type Traffic struct {
	Id       int   `json:"subscription_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

// AliveIP is the wire format for ReportOnlineIPs.
type AliveIP struct {
	Id int    `json:"subscription_id"`
	IP string `json:"ip"`
}

// ServerStatus holds the machine health metrics sent to the panel.
type ServerStatus struct {
	CPU       float64 `json:"cpu"`
	MemUsed   uint64  `json:"mem"`
	MemTotal  uint64  `json:"mem_total"`
	SwapUsed  uint64  `json:"swap"`
	SwapTotal uint64  `json:"swap_total"`
	DiskUsed  uint64  `json:"disk"`
	DiskTotal uint64  `json:"disk_total"`
	Load1     float64 `json:"load1"`
	Load5     float64 `json:"load5"`
	Load15    float64 `json:"load15"`
	NetIn     float64 `json:"net_in"`
	NetOut    float64 `json:"net_out"`
	Uptime    uint64  `json:"uptime"`
}

// ServerStatusPayload is the Reverb push envelope for server_status events.
type ServerStatusPayload struct {
	ServerID int           `json:"server_id"`
	Data     *ServerStatus `json:"data"`
}

// ServerNode holds the node_id for a single node assigned to a machine.
type ServerNode struct {
	NodeID int `json:"node_id"`
}

// ServerNodesResponse is the response from /api/server/nodes/{machine}.
type ServerNodesResponse struct {
	Nodes        []*ServerNode `json:"nodes"`
	PollInterval int           `json:"poll_interval"`
	Version      int           `json:"api_version"`
}
