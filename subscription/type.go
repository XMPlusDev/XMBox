package subscription

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	inboundprotocol "github.com/xmplusdev/xmbox/inbound/protocol"
)

type VLESSUserManager interface {
	AddUsers(users []option.VLESSUser) error
	DelUsers(emails []string) error
}

type VMessUserManager interface {
	AddUsers(users []option.VMessUser) error
	DelUsers(emails []string) error
}

type TrojanUserManager interface {
	AddUsers(users []option.TrojanUser) error
	DelUsers(emails []string) error
}

type TUICUserManager interface {
	AddUsers(users []option.TUICUser) error
	DelUsers(emails []string) error
}

type Hysteria2UserManager interface {
	AddUsers(users []option.Hysteria2User) error
	DelUsers(emails []string) error
}

type NaiveUserManager interface {
	AddUsers(users []auth.User) error
	DelUsers(emails []string) error
}

type ShadowsocksUserManager interface {
	AddUsers(users []option.ShadowsocksUser) error
	DelUsers(emails []string) error
}

// ShadowTLSUserManager takes inboundprotocol.ShadowTLSUser rather than
// option.ShadowTLSUser because a ShadowTLS node stacks two protocols: each
// subscription needs a ShadowTLS credential and a key for the inner
// shadowsocks layer that carries destinations and encrypts traffic.
type ShadowTLSUserManager interface {
	AddUsers(users []inboundprotocol.ShadowTLSUser) error
	DelUsers(emails []string) error
}

type AnyTLSUserManager interface {
	AddUsers(users []option.AnyTLSUser) error
	DelUsers(emails []string) error
}
