package node

import (
	"github.com/xmplusdev/xmbox/cert"
	"github.com/xmplusdev/xmbox/instance"
)

// Config holds node-level configuration used by the Manager and builder.
type Config struct {
	CertConfig          *cert.CertConfig          `mapstructure:"CertConfig"`
	InstanceConfig      *InstanceConfig           `mapstructure:"InstanceConfig"`
	DisableNodeMonitor  bool                      `mapstructure:"DisableNodeMonitor"`
}

// InstanceConfig carries per-node instance settings (e.g. multiplex).
type InstanceConfig struct {
	MultiplexConfig *instance.MultiplexConfig `mapstructure:"MultiplexConfig"`
}
