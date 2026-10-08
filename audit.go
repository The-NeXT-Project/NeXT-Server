package nextserver

import (
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
)

// auditor matches connections against the panel's detect rules and keeps
// the hits until they are reported.
type auditor struct {
	rules atomic.Pointer[[]adapter.DetectRule]

	access sync.Mutex
	hits   map[adapter.DetectLog]struct{}
}

func newAuditor() *auditor {
	return &auditor{hits: make(map[adapter.DetectLog]struct{})}
}

func (a *auditor) setRules(rules []adapter.DetectRule) {
	a.rules.Store(&rules)
}

func (a *auditor) enabled() bool {
	rules := a.rules.Load()
	return rules != nil && len(*rules) > 0
}

// match returns the first rule that matches the connection. Plain rules see
// the destination host, the sniffed domain and the first payload as text; hex
// rules see the payload hex encoded, as the panel's rule types describe.
func (a *auditor) match(host string, domain string, payload []byte) (adapter.DetectRule, bool) {
	rules := a.rules.Load()
	if rules == nil {
		return adapter.DetectRule{}, false
	}
	var hexPayload string
	for _, rule := range *rules {
		switch rule.Type {
		case adapter.DetectRuleTypeHex:
			if len(payload) == 0 {
				continue
			}
			if hexPayload == "" {
				hexPayload = hex.EncodeToString(payload)
			}
			if rule.Regexp.MatchString(hexPayload) {
				return rule, true
			}
		default:
			if (host != "" && rule.Regexp.MatchString(host)) ||
				(domain != "" && domain != host && rule.Regexp.MatchString(domain)) ||
				(len(payload) > 0 && rule.Regexp.Match(payload)) {
				return rule, true
			}
		}
	}
	return adapter.DetectRule{}, false
}

func (a *auditor) record(userID int, ruleID int) {
	a.access.Lock()
	a.hits[adapter.DetectLog{UserID: userID, RuleID: ruleID}] = struct{}{}
	a.access.Unlock()
}

func (a *auditor) collect() []adapter.DetectLog {
	a.access.Lock()
	defer a.access.Unlock()
	if len(a.hits) == 0 {
		return nil
	}
	logs := make([]adapter.DetectLog, 0, len(a.hits))
	for hit := range a.hits {
		logs = append(logs, hit)
	}
	clear(a.hits)
	return logs
}

func (a *auditor) restore(logs []adapter.DetectLog) {
	a.access.Lock()
	for _, log := range logs {
		a.hits[log] = struct{}{}
	}
	a.access.Unlock()
}
