package instance

import (
	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/cert"
	"github.com/xmplusdev/xmbox/limiter"
)

// Config is the top-level configuration parsed from config.yaml.
type Config struct {
	InstanceConfig *InstanceConfig      `mapstructure:"InstanceConfig"`
	ApiConfig      *api.Config `mapstructure:"ApiConfig"`
	RedisConfig *limiter.RedisConfig `mapstructure:"RedisConfig"`
	CertConfig *cert.CertConfig `mapstructure:"CertConfig"`
    ReverbConfig []*ReverbConfig `mapstructure:"ReverbConfig"`
}

type NodesConfig struct {
	ApiConfig  *api.Config          `mapstructure:"ApiConfig"`
	CertConfig *cert.CertConfig     `mapstructure:"CertConfig"`
}

type InstanceConfig struct {
	LogConfig       *LogConfig       `mapstructure:"LogConfig"`
	NtpConfig       *NtpConfig       `mapstructure:"NtpConfig"`
	DNSConfig       *DNSConfig       `mapstructure:"DNSConfig"`
	RouteConfig     *RouteConfig     `mapstructure:"RouteConfig"`
	MultiplexConfig *MultiplexConfig `mapstructure:"MultiplexConfig"`
}

// MultiplexConfig configures sing-box inbound multiplexing.
type MultiplexConfig struct {
	Enabled bool `mapstructure:"Enabled"`
	Padding bool `mapstructure:"Padding"`
}
// LogConfig controls sing-box log output.
type LogConfig struct {
	Level    string `mapstructure:"Level"`
	Output   string `mapstructure:"Output"`
	Disabled bool   `mapstructure:"Disabled"`
}

// NtpConfig enables NTP synchronisation inside sing-box.
type NtpConfig struct {
	Enable     bool   `mapstructure:"Enable"`
	Server     string `mapstructure:"Server"`
	ServerPort uint16 `mapstructure:"ServerPort"`
}

type DNSConfig struct {
	Enable   bool   `mapstructure:"Enable"`
	Path     string `mapstructure:"Path"`
}

type RouteConfig struct {
	Enable     bool   `mapstructure:"Enable"`
	Path       string `mapstructure:"Path"`
}

// ReverbConfig describes a Laravel Reverb WebSocket server to listen on.
type ReverbConfig struct {
	Enable    bool   `mapstructure:"Enable"`
	Host      string `mapstructure:"Host"`
	AppKey    string `mapstructure:"AppKey"`
	AppSecret string `mapstructure:"AppSecret"`
	UseTLS    bool   `mapstructure:"UseTLS"`
}

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{Level: "info", Output: "", Disabled: false}
}

