package subscription

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

type VLESSUserManager interface {
	AddUsers(users []option.VLESSUser) error
	DelUsers(names []string) error
}

type VMessUserManager interface {
	AddUsers(users []option.VMessUser) error
	DelUsers(names []string) error
}

type TrojanUserManager interface {
	AddUsers(users []option.TrojanUser) error
	DelUsers(names []string) error
}

type TUICUserManager interface {
	AddUsers(users []option.TUICUser) error
	DelUsers(names []string) error
}

type Hysteria2UserManager interface {
	AddUsers(users []option.Hysteria2User) error
	DelUsers(names []string) error
}

type NaiveUserManager interface {
	AddUsers(users []auth.User) error
	DelUsers(names []string) error
}

type ShadowsocksUserManager interface {
	AddUsers(users []option.ShadowsocksUser) error
	DelUsers(names []string) error
}

type ShadowTLSUserManager interface {
	AddUsers(users []option.ShadowTLSUser) error
	DelUsers(names []string) error
}

type AnyTLSUserManager interface {
	AddUsers(users []option.AnyTLSUser) error
	DelUsers(names []string) error
}