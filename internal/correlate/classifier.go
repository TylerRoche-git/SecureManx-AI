package correlate

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// windowEntry holds an event together with its arrival time and any enrichments
// attached by the pre-filter stage.
type windowEntry struct {
	event       *eventschema.Event
	addedAt     time.Time
	enrichments map[string]any
}

// Classifier implements Stage 2 of the three-stage decision path: multi-signal
// correlation within a sliding time window, grouped by workload ID.
type Classifier struct {
	mu             sync.Mutex
	windowDuration time.Duration
	windows        map[string][]windowEntry // keyed by workload_id
}

// NewClassifier creates a Classifier with the given sliding window duration.
func NewClassifier(windowDuration time.Duration) *Classifier {
	return &Classifier{
		windowDuration: windowDuration,
		windows:        make(map[string][]windowEntry),
	}
}

// evictExpired returns only the entries that fall within the window duration
// relative to the current time.
func (c *Classifier) evictExpired(entries []windowEntry) []windowEntry {
	cutoff := time.Now().Add(-c.windowDuration)
	kept := entries[:0]
	for _, e := range entries {
		if e.addedAt.After(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

// Correlate adds an event to the correlation window and checks for multi-signal
// patterns. It returns an Incident if the accumulated evidence crosses the
// correlation threshold, or nil if the event is absorbed without triggering.
func (c *Classifier) Correlate(_ context.Context, event *eventschema.Event, enrichments map[string]any) (*eventschema.Incident, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	wid := event.WorkloadID

	// Step 1: Expire old entries.
	c.windows[wid] = c.evictExpired(c.windows[wid])

	// Step 2: Add the new event.
	c.windows[wid] = append(c.windows[wid], windowEntry{
		event:       event,
		addedAt:     time.Now(),
		enrichments: enrichments,
	})

	entries := c.windows[wid]

	// Step 3: Score the window.
	signalSet := make(map[string]struct{})
	var maxSeverity eventschema.Severity
	var maxConfidence float64

	for _, entry := range entries {
		if entry.event.SignalClass != "" {
			signalSet[entry.event.SignalClass] = struct{}{}
		}
		if severityRank(entry.event.Severity) > severityRank(maxSeverity) {
			maxSeverity = entry.event.Severity
		}
		if entry.event.Confidence > maxConfidence {
			maxConfidence = entry.event.Confidence
		}
	}

	distinctSignals := len(signalSet)
	baseScore := maxConfidence * (1.0 + 0.15*float64(distinctSignals-1))
	if baseScore > 1.0 {
		baseScore = 1.0
	}
	if baseScore < 0.0 {
		baseScore = 0.0
	}

	// Step 4: Check triggering conditions.
	triggered := baseScore >= 0.3 ||
		len(entries) >= 3 ||
		maxSeverity == eventschema.SeverityCritical

	if !triggered {
		return nil, nil
	}

	// Build the incident from all events in the window.
	eventIDs := make([]uuid.UUID, 0, len(entries))
	threatCategories := make(map[string]struct{})

	for _, entry := range entries {
		eventIDs = append(eventIDs, entry.event.EventID)
		if entry.enrichments != nil {
			if cat, ok := entry.enrichments["threat_category"]; ok {
				if s, ok := cat.(string); ok && s != "" {
					threatCategories[s] = struct{}{}
				}
			}
		}
	}

	incident := eventschema.NewIncident(eventIDs)
	incident.ConfidenceScore = baseScore

	// Build threat hypothesis from distinct threat categories.
	if len(threatCategories) > 0 {
		categories := make([]string, 0, len(threatCategories))
		for cat := range threatCategories {
			categories = append(categories, cat)
		}
		incident.ThreatHypothesis = "correlated signals: " + strings.Join(categories, ", ")
	} else {
		incident.ThreatHypothesis = "multi-signal correlation triggered"
	}

	incident.AssetCriticality = maxSeverity

	// Clear the window for this workload (incident consumed the evidence).
	delete(c.windows, wid)

	return &incident, nil
}

// ActiveWindows returns the count of non-empty correlation windows.
func (c *Classifier) ActiveWindows() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for _, entries := range c.windows {
		if len(entries) > 0 {
			count++
		}
	}
	return count
}
