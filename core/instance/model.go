package instance

import (
	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/helper/cert"
	"github.com/xmplusdev/xmbox/helper/limiter"
)

type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	NtpConfig    	   *NtpConfig 		 `mapstructure:"Ntp"`
	DnsConfig          string            `mapstructure:"DnsFile"`
	RouteConfig        string            `mapstructure:"RouteFile"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
	ReverbConfig       []*ReverbConfig   `mapstructure:"ReverbConfig"`
}

type NodesConfig struct {
	ApiConfig        *api.Config          `mapstructure:"ApiConfig"`
	CertConfig       *cert.CertConfig     `mapstructure:"CertConfig"`
	RedisConfig      *limiter.RedisConfig `mapstructure:"RedisConfig"`
}

type LogConfig struct {
	Level string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Disabled bool `mapstructure:"Disabled"`
}

type ReverbConfig struct {
    Enable    bool   	`mapstructure:"Enable"`
    Host      string 	`mapstructure:"Host"`      
    AppKey    string 	`mapstructure:"AppKey"`   
	AppSecret string 	`mapstructure:"AppSecret"` 
    Channel   string 	`mapstructure:"Channel"`   
    UseTLS    bool   	`mapstructure:"UseTLS"` 
}

type NtpConfig struct {
	Enable     bool   `mapstructure:"Enable"`
	Server     string `mapstructure:"Server"`
	ServerPort uint16 `mapstructure:"ServerPort"`
}

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:  "info",
		Output: "",
		Disabled: false,
	}
}

