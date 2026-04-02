package correlate

import (
	"strings"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// severityRank maps a Severity value to a numeric rank for comparison.
// critical=4, high=3, medium=2, low=1, unknown/empty=0.
func severityRank(s eventschema.Severity) int {
	switch s {
	case eventschema.SeverityCritical:
		return 4
	case eventschema.SeverityHigh:
		return 3
	case eventschema.SeverityMedium:
		return 2
	case eventschema.SeverityLow:
		return 1
	default:
		return 0
	}
}

// Rule represents a single pre-filter rule used in Stage 1 deterministic filtering.
type Rule struct {
	Name          string         `json:"name"`
	SignalClass   string         `json:"signal_class"`
	MinSeverity   eventschema.Severity `json:"min_severity"`
	MinConfidence float64        `json:"min_confidence"`
	Enrichments   map[string]any `json:"enrichments"`
}

// matchesSignalClass returns true if the event's SignalClass contains the rule's
// SignalClass substring (case-insensitive via the stored lowercase pattern).
// An empty SignalClass on the rule matches all events.
func (r *Rule) matchesSignalClass(eventSignalClass string) bool {
	if r.SignalClass == "" {
		return true
	}
	lower := strings.ToLower(eventSignalClass)
	for _, token := range strings.Split(r.SignalClass, "|") {
		if strings.Contains(lower, strings.TrimSpace(token)) {
			return true
		}
	}
	return false
}

// matchesSeverity returns true if the event's severity is at or above the rule's
// minimum severity. An empty MinSeverity on the rule matches all events.
func (r *Rule) matchesSeverity(eventSeverity eventschema.Severity) bool {
	if r.MinSeverity == "" {
		return true
	}
	return severityRank(eventSeverity) >= severityRank(r.MinSeverity)
}

// matchesConfidence returns true if the event's confidence is at or above the
// rule's minimum confidence. A MinConfidence of 0 matches all events.
func (r *Rule) matchesConfidence(eventConfidence float64) bool {
	if r.MinConfidence == 0 {
		return true
	}
	return eventConfidence >= r.MinConfidence
}

// PreFilter implements Stage 1 of the three-stage decision path: deterministic
// rule-based filtering using signatures, thresholds, and signal class matching.
type PreFilter struct {
	rules []Rule
}

// NewPreFilter creates a PreFilter initialised with the default rule set.
// Rules are evaluated in order; an event passes if any rule matches.
func NewPreFilter() *PreFilter {
	pf := &PreFilter{}

	pf.rules = []Rule{
		{
			Name:        "high-severity-pass",
			MinSeverity: eventschema.SeverityHigh,
		},
		{
			Name:        "credential-access",
			SignalClass: "credential",
			Enrichments: map[string]any{"threat_category": "credential-theft"},
		},
		{
			Name:        "exfiltration-pattern",
			SignalClass: "egress|exfiltration",
			Enrichments: map[string]any{"threat_category": "data-exfiltration"},
		},
		{
			Name:        "supply-chain-anomaly",
			SignalClass: "dependency|hash|unsigned",
			Enrichments: map[string]any{"threat_category": "supply-chain"},
		},
		{
			Name:        "privilege-escalation",
			SignalClass: "privilege|escalation",
		},
		{
			Name:          "default-pass",
			MinConfidence: 0.2,
		},
	}

	return pf
}

// AddRule appends a custom rule to the pre-filter's rule set.
func (p *PreFilter) AddRule(rule Rule) {
	p.rules = append(p.rules, rule)
}

// Evaluate checks an event against all rules. It returns true if any rule
// matches, along with the merged enrichments from every matching rule.
func (p *PreFilter) Evaluate(event *eventschema.Event) (pass bool, enrichments map[string]any) {
	enrichments = make(map[string]any)

	for _, rule := range p.rules {
		if !rule.matchesSignalClass(event.SignalClass) {
			continue
		}
		if !rule.matchesSeverity(event.Severity) {
			continue
		}
		if !rule.matchesConfidence(event.Confidence) {
			continue
		}

		// Rule matched.
		pass = true
		for k, v := range rule.Enrichments {
			enrichments[k] = v
		}
	}

	return pass, enrichments
}
