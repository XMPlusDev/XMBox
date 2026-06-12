package api

// API is the interface every panel API client must satisfy.
type API interface {
	// Describe returns static connection info for logging.
	Describe() ClientInfo

	// Node endpoints
	GetNodeInfo() (*NodeInfo, error)
	GetNodeRule() (*[]DetectRules, error)
	GetTransitNode() (*RelayNodeInfo, error)

	// Subscription endpoints
	GetSubscriptionList() (*[]SubscriptionInfo, error)
	ReportTraffic(*[]SubscriptionTraffic) error
	ReportOnlineIPs(*[]OnlineIP) error

	// Machine / server-ID endpoints (only used when ServerID > 0)
	GetServerNodes() (*ServerNodesResponse, error)
	ReportServerStatus(serverID int, status *ServerStatus) error
}
