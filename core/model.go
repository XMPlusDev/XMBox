package core

import (
	"github.com/xmplusdev/xmbox/api"
)

type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	NtpConfig    	   *NtpConfig 		 `mapstructure:"Ntp"`
	DnsConfig          string            `mapstructure:"DnsFile"`
	RouteConfig        string            `mapstructure:"RouteFile"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
}

type NodesConfig struct {
	ApiConfig        *api.Config    `mapstructure:"ApiConfig"`
}

type LogConfig struct {
	Level string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Disabled bool `mapstructure:"Disabled"`
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

