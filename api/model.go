package api

import (
	"encoding/json"
	"regexp"
)

const (
	SubscriptionNotModified = "subscriptions_not_modified"
	NodeNotModified = "node_not_modified"
	RuleNotModified = "rules_not_modified"
)

type Config struct {
	APIHost 		string 		`mapstructure:"ApiHost"`
	NodeID  		int    		`mapstructure:"NodeID"`
	APIKey     		string 		`mapstructure:"ApiKey"`
	Timeout 		int    		`mapstructure:"Timeout"`
}

type Response struct {
	Data 				json.RawMessage 	`json:"data"`
}

type PostData struct {
	Key  			string      			`json:"key"`
	Data 			interface{} 			`json:"data"`
}

type serverConfig struct {
	server  `json:"server"`
}

type server struct {
	Protocol        	string 				`json:"type"`
	ServerSpeedlimit  	int    			 	`json:"speed_limit"`
	ServerKey  	        string    			`json:"server_key"`
	Addr                string   			`json:"address"`
	IP                  string   			`json:"ip"`
	NetworkSettings     *json.RawMessage 	`json:"transportSettings"`
	SecuritySettings    *json.RawMessage 	`json:"securitySettings"`
	UpdateInterval   	int 				`json:"update_interval"`
	RulesSettings       []rule              `json:"rules"`
}

type rule struct {
	Id       int      `json:"id"`
	Regex    string   `json:"value"`
}

type SubscriptionResponse struct {
	Data 	json.RawMessage 	`json:"subscriptions"`
}

type Subscription struct {
	Id         	int    		`json:"id"`
	UUID     	string 		`json:"passwd"`
	Speedlimit 	int    		`json:"speed_limit"`
	Iplimit    	int    		`json:"ip_limit"`
}

type NetworkSettings struct {
	Type     	string   	
	Cipher      string     
	
	// WebSocket
	Path    string  
	Host    string  
	Method  string  	
	HeaderType string
	Headers map[string]string 
	
	MaxEarlyData  uint32   

	// gRPC
	ServiceName string 		
	
	//Hysteria
	ObfsType    string     
	ObfsPasswd  string		
	BBRProfile  string    	
	IgnoreClientBandwidth  bool 
	
	// TUIC congestion control: bbr | cubic | new_reno
	CongestionControl string 
	
	// Flow xtls
	Flow     string
	
	//Shasowtls
	HandshakeServer 	string
	HandshakePort 		uint16 
	StrictMode          bool  
	
	// anytls
	PaddingScheme  []string
}

// TLSSettings holds TLS and REALITY configuration.
type TlsSettings struct {
	Type    		string 	 
	Enabled         bool 
    CertMode	    string
	ServerName      string   
	Alpn            []string 
	EnabledECH      bool  	 
	ECHKey		    []string 
 
	RealityEnabled     bool 
	RealityPrivateKey  string 
	RealityShortID     []string 
	RealityServerName  string
	RealityServerPort  uint16 
}


type NodeInfo struct {
	ID          	int
	ServerKey       string
	Protocol        string
	SpeedLimit      uint64
	UpdateInterval  int
	ListenAddr      string  
	ListenPort      uint16    	
	TCPFastOpen     bool		
	TlsSettings     *TlsSettings
	NetworkSettings *NetworkSettings
}

type SubscriptionInfo struct {
	Id           int
	UUID         string
	SpeedLimit   uint64
	IPLimit      int
}

// Reports Data
type OnlineIP struct {
	Id  int
	IP  string
}

type SubscriptionTraffic struct {
	Id  int
	Upload   int64
	Download   int64
}

type Traffic struct {
	Id  		int   		`json:"subscription_id"`
	Upload   	int64 		`json:"u"`
	Download   	int64 		`json:"d"`
}

type AliveIP struct {
	Id 		int    		`json:"subscription_id"`
	IP  	string 		`json:"ip"`
}

type DetectRules struct {
	ID      int
	Pattern *regexp.Regexp
}