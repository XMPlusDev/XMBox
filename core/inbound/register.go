package inbound

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/xmplusdev/xmbox/core/inbound/protocol"
)

func RegisterAll(registry *inbound.Registry) {
	protocol.RegisterVLESS(registry)
	protocol.RegisterVMess(registry)
	protocol.RegisterTrojan(registry)
	protocol.RegisterTUIC(registry)
	protocol.RegisterHysteria2(registry)
	protocol.RegisterNaive(registry)
	protocol.RegisterShadowTLS(registry)
	protocol.RegisterShadowsocks(registry)
	protocol.RegisterAnyTLS(registry)
}
