// Command control-plane runs the security-brain control plane, wiring
// together ingestion, correlation, policy evaluation, playbook execution,
// audit recording, and the operator API.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/security-brain/security-brain/internal/alerting"
	"github.com/security-brain/security-brain/internal/api"
	"github.com/security-brain/security-brain/internal/audit"
	"github.com/security-brain/security-brain/internal/correlate"
	"github.com/security-brain/security-brain/internal/domain"
	"github.com/security-brain/security-brain/internal/incidents"
	"github.com/security-brain/security-brain/internal/ingest"
	"github.com/security-brain/security-brain/internal/normalize"
	"github.com/security-brain/security-brain/internal/playbooks"
	"github.com/security-brain/security-brain/internal/policy"
	"github.com/security-brain/security-brain/internal/sentinel"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

func main() {
	slog.Info("security-brain control plane starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. Load config.
	cfg, err := domain.LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// 1b. Configure alerting sinks based on environment.
	var alertSinks []alerting.Sink
	if cfg.SlackWebhookURL != "" {
		alertSinks = append(alertSinks, alerting.NewSlackSink(cfg.SlackWebhookURL, cfg.SlackChannel))
		slog.Info("alerting sink enabled", "sink", "slack", "channel", cfg.SlackChannel)
	}
	if cfg.PagerDutyKey != "" {
		alertSinks = append(alertSinks, alerting.NewPagerDutySink(cfg.PagerDutyKey))
		slog.Info("alerting sink enabled", "sink", "pagerduty")
	}
	if cfg.AlertWebhookURL != "" {
		alertSinks = append(alertSinks, alerting.NewWebhookSink(cfg.AlertWebhookURL, nil))
		slog.Info("alerting sink enabled", "sink", "webhook", "url", cfg.AlertWebhookURL)
	}
	alertRouter := alerting.NewRouter(alertSinks...)
	slog.Info("alerting router created", "sinks", len(alertSinks))

	// 2. Connect NATS.
	slog.Info("connecting to NATS", "url", cfg.NATSUrl)
	natsClient, err := transport.NewNATSClient(cfg.NATSUrl)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer natsClient.Close()

	// 3. Create JetStream streams.
	if err := natsClient.CreateAllStreams(ctx); err != nil {
		slog.Error("failed to create JetStream streams", "error", err)
		os.Exit(1)
	}

	// 4. Connect PostgreSQL.
	slog.Info("connecting to PostgreSQL")
	auditStore, err := audit.NewStore(ctx, cfg.PostgresDSN)
	if err != nil {
		slog.Error("failed to connect to PostgreSQL for audit store", "error", err)
		os.Exit(1)
	}
	defer auditStore.Close()

	incidentStore, err := incidents.NewStore(ctx, cfg.PostgresDSN)
	if err != nil {
		slog.Error("failed to connect to PostgreSQL for incident store", "error", err)
		os.Exit(1)
	}
	defer incidentStore.Close()

	// 5. Build components.
	auditWriter := audit.NewWriter(auditStore)
	eventBus := transport.NewEventBus(natsClient)
	normalizer := normalize.NewNormalizer()
	ingester := ingest.NewIngester(natsClient, eventBus, normalizer)

	preFilter := correlate.NewPreFilter()
	classifier := correlate.NewClassifier(cfg.CorrelationWindow)
	policyEval, err := policy.NewEvaluator(cfg.PolicyDir)
	if err != nil {
		slog.Error("failed to create policy evaluator", "error", err)
		os.Exit(1)
	}
	engine := correlate.NewEngine(preFilter, classifier, policyEval)

	playbookReg, err := playbooks.NewRegistry(cfg.PlaybooksDir)
	if err != nil {
		slog.Error("failed to create playbook registry", "error", err)
		os.Exit(1)
	}
	executor := playbooks.NewExecutor(playbookReg, eventBus, auditWriter)

	// 6. Create sentinel for control plane self-integrity monitoring.
	binaryPath, _ := os.Executable()
	sen := sentinel.NewSentinel(binaryPath, cfg.PolicyDir, eventBus, natsClient)

	// 7. Subscribe to normalized events, process through engine, execute playbooks.
	_, err = eventBus.SubscribeNormalized(ctx, "control-plane-processor", func(event eventschema.Event) {
		if recErr := auditWriter.RecordDetection(ctx, &event); recErr != nil {
			slog.Error("audit record detection failed", "error", recErr)
		}

		incident, procErr := engine.Process(ctx, &event)
		if procErr != nil {
			slog.Error("correlation error", "error", procErr)
			return
		}
		if incident == nil {
			return
		}

		slog.Info("incident created",
			"id", incident.IncidentID,
			"hypothesis", incident.ThreatHypothesis,
		)

		if insertErr := incidentStore.Insert(ctx, incident); insertErr != nil {
			slog.Error("failed to store incident", "error", insertErr, "id", incident.IncidentID)
		}

		if recErr := auditWriter.RecordCorrelation(ctx, incident); recErr != nil {
			slog.Error("audit record correlation failed", "error", recErr)
		}

		if incident.PolicyDecision.Action != policytypes.ActionDetectOnly {
			if alertErr := alertRouter.Alert(ctx, alerting.Alert{
				Severity:   alerting.SeverityCritical,
				Title:      "Security Incident: " + incident.ThreatHypothesis,
				Message:    fmt.Sprintf("Action: %s, Confidence: %.2f", incident.PolicyDecision.Action, incident.ConfidenceScore),
				IncidentID: incident.IncidentID.String(),
				Action:     string(incident.PolicyDecision.Action),
			}); alertErr != nil {
				slog.Error("alert delivery failed", "error", alertErr, "incident_id", incident.IncidentID)
			}

			if execErr := executor.Execute(ctx, incident); execErr != nil {
				slog.Error("playbook execution error", "error", execErr)
				incident.ExecutionStatus = eventschema.StatusFailed
			} else {
				incident.ExecutionStatus = eventschema.StatusCompleted
			}
			if updateErr := incidentStore.Update(ctx, incident); updateErr != nil {
				slog.Error("failed to update incident status", "error", updateErr, "id", incident.IncidentID)
			}
		}
	})
	if err != nil {
		slog.Error("failed to subscribe to normalized events", "error", err)
		os.Exit(1)
	}

	// 8. Start ingester, API server, and sentinel.
	apiServer := api.NewServer(cfg.APIAddr, auditStore, incidentStore, playbookReg)

	var g errgroup.Group
	g.Go(func() error { return ingester.Start(ctx) })
	g.Go(func() error { return apiServer.Start(ctx) })
	g.Go(func() error { return sen.Start(ctx) })

	slog.Info("control plane ready", "api", cfg.APIAddr)

	if err := g.Wait(); err != nil {
		slog.Error("component error", "error", err)
	}

	// Graceful shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	sen.Stop()
	if err := ingester.Stop(shutdownCtx); err != nil {
		slog.Error("ingester shutdown error", "error", err)
	}
	if err := apiServer.Stop(shutdownCtx); err != nil {
		slog.Error("api server shutdown error", "error", err)
	}

	slog.Info("control plane stopped")
}
