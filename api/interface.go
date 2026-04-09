package api

type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetSubscriptionList() (subscriptionList *[]SubscriptionInfo, err error)
	ReportOnlineIPs(onlineIP *[]OnlineIP) (err error)
	ReportTraffic(subscriptionTraffic *[]SubscriptionTraffic) (err error)
	GetNodeRule() (rules *[]DetectRules, err error)
	Describe() ClientInfo
	Debug()
}
