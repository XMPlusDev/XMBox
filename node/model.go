package node

import (
	"github.com/xmplusdev/xmbox/helper/cert"
	"github.com/xmplusdev/xmbox/helper/limiter"
)

type Config struct {
	CertConfig      *cert.CertConfig     `mapstructure:"CertConfig"`
	RedisConfig     *limiter.RedisConfig `mapstructure:"RedisConfig"`
	Multiplex       *Multiplex           `mapstructure:"Multiplex"`
}

type Multiplex struct {
	Enabled    bool   `mapstructure:"Enabled"`
	Padding    bool   `mapstructure:"Padding"`
}
