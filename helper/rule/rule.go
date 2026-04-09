package rule

import (
	"reflect"
	"sync"
	"fmt"

	"github.com/xmplusdev/xmbox/api"
)

var ruleManager = New()

func GetRuleManager(tag string) (*Manager, error) {
	if _, ok := ruleManager.InboundRule.Load(tag); !ok {
		return nil, fmt.Errorf("no rule found for inbound: %s", tag)
	}
	return ruleManager, nil
}

func UpdateRule(tag string, rules []api.DetectRules) error {
	return ruleManager.UpdateRule(tag, rules)
}

type Manager struct {
	InboundRule         *sync.Map 
}

func New() *Manager {
	return &Manager{
		InboundRule:   new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRules) error {
	if value, ok := r.InboundRule.LoadOrStore(tag, newRuleList); ok {
		oldRuleList := value.([]api.DetectRules)
		if !reflect.DeepEqual(oldRuleList, newRuleList) {
			r.InboundRule.Store(tag, newRuleList)
		}
	}
	return nil
}

func (r *Manager) CheckRule(tag string, destination string) bool {
	value, ok := r.InboundRule.Load(tag)
	if !ok {
		return false
	}
	for _, rule := range value.([]api.DetectRules) {
		if rule.Pattern.MatchString(destination) {
			return true
		}
	}
	return false
}