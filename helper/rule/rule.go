package rule

import (
	"fmt"
	"sync"

	"github.com/xmplusdev/xmbox/api"
)

// Manager holds compiled blocking rules for inbound tags.
type Manager struct {
	InboundRule *sync.Map // tag → []api.DetectRules
}

var globalManager = &Manager{InboundRule: new(sync.Map)}

// UpdateRule replaces the rule set for a tag.
func UpdateRule(tag string, rules []api.DetectRules) error {
	globalManager.InboundRule.Store(tag, rules)
	return nil
}

// GetRuleManager returns the global manager (used by dispatcher).
func GetRuleManager(tag string) (*Manager, error) {
	if _, ok := globalManager.InboundRule.Load(tag); !ok {
		return nil, fmt.Errorf("no rules for tag: %s", tag)
	}
	return globalManager, nil
}

// CheckRule returns true if destination matches any blocking rule for tag.
func (m *Manager) CheckRule(tag, destination string) bool {
	v, ok := m.InboundRule.Load(tag)
	if !ok {
		return false
	}
	for _, r := range v.([]api.DetectRules) {
		if r.Pattern != nil && r.Pattern.MatchString(destination) {
			return true
		}
	}
	return false
}
