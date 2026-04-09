package node

import (
	"fmt"

	F "github.com/sagernet/sing/common/format"
	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/core"
)

type Manager struct {
	coreInstance *core.Instance
}

func NewManager(coreInstance *core.Instance) *Manager {
	return &Manager{coreInstance: coreInstance}
}

func (m *Manager) AddNode(nodeInfo *api.NodeInfo, tag string, config *Config) error {
	inbound, err := getInboundOptions(tag, nodeInfo, config)
	if err != nil {
		return fmt.Errorf("failed to build inbound config: %w", err)
	}

	b := m.coreInstance.GetBox()
	err = b.Inbound().Create(
		m.coreInstance.GetCtx(),
		b.Router(),
		m.coreInstance.GetLogFactory().NewLogger(
			F.ToString("inbound/", inbound.Type, "[", tag, "]"),
		),
		tag,
		inbound.Type,
		inbound.Options,
	)
	if err != nil {
		return fmt.Errorf("create inbound %q: %w", tag, err)
	}

	return nil
}

func (m *Manager) RemoveNode(tag string) error {
	b := m.coreInstance.GetBox()
	if _, found := b.Inbound().Get(tag); found {
		if err := b.Inbound().Remove(tag); err != nil {
			return fmt.Errorf("remove inbound %q: %w", tag, err)
		}
	}
	return nil
}