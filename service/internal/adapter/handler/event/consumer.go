package event

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"

	"github.com/sentiae/vigil/service/internal/domain"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/internal/usecase"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// parseEventData unmarshals the CloudEvent Data (json.RawMessage) into EventData.
func parseEventData(raw json.RawMessage) (events.EventData, error) {
	var data events.EventData
	if err := json.Unmarshal(raw, &data); err != nil {
		return data, err
	}
	return data, nil
}

// Consumer subscribes to other Sentiae services' Kafka topics and auto-triggers scans.
type Consumer struct {
	scanUC         portuc.ScanUseCase
	graphRefresher *usecase.GraphRefresher
	brokers        []string
	groupID        string
	readers        []*kafka.Reader
}

// NewConsumer creates a Kafka event consumer.
func NewConsumer(scanUC portuc.ScanUseCase, brokers []string, groupID string) *Consumer {
	return &Consumer{
		scanUC:  scanUC,
		brokers: brokers,
		groupID: groupID,
	}
}

// WithGraphRefresher wires the §11.3 incremental-graph refresh hook.
// Separate from the constructor so existing call sites don't need to
// change and so the refresher stays optional in minimal deployments.
func (c *Consumer) WithGraphRefresher(r *usecase.GraphRefresher) *Consumer {
	c.graphRefresher = r
	return c
}

// Start begins consuming events from all subscribed topics.
func (c *Consumer) Start(ctx context.Context) {
	topics := []struct {
		topic   string
		handler func(ctx context.Context, msg kafka.Message)
	}{
		{"sentiae.git.events", c.handleGitEvent},
		{"sentiae.ops.events", c.handleOpsEvent},
		{"sentiae.canvas.events", c.handleCanvasEvent},
	}

	for _, t := range topics {
		reader := kafka.NewReader(kafka.ReaderConfig{
			Brokers:  c.brokers,
			Topic:    t.topic,
			GroupID:  c.groupID,
			MinBytes: 1,
			MaxBytes: 10e6,
			MaxWait:  1 * time.Second,
		})
		c.readers = append(c.readers, reader)

		go c.consumeLoop(ctx, reader, t.topic, t.handler)
	}

	logger.Info(ctx, "Kafka consumers started", "topics", []string{"sentiae.git.events", "sentiae.ops.events", "sentiae.canvas.events"})
}

// Stop closes all Kafka readers.
func (c *Consumer) Stop() {
	for _, r := range c.readers {
		_ = r.Close()
	}
}

func (c *Consumer) consumeLoop(ctx context.Context, reader *kafka.Reader, topic string, handler func(ctx context.Context, msg kafka.Message)) {
	for {
		msg, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // Context cancelled, shutting down
			}
			logger.Error(ctx, "Kafka read error", "topic", topic, "error", err)
			time.Sleep(1 * time.Second)
			continue
		}

		handler(ctx, msg)
	}
}

func (c *Consumer) handleGitEvent(ctx context.Context, msg kafka.Message) {
	var event events.CloudEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		logger.Warn(ctx, "Failed to parse git event", "error", err)
		return
	}

	data, err := parseEventData(event.Data)
	if err != nil {
		logger.Warn(ctx, "Failed to parse git event data", "error", err)
		return
	}

	switch event.Type {
	case "sentiae.git.push", "sentiae.git.push.received", "sentiae.git.change.created":
		// §11.3 — incremental graph refresh for the changed files.
		// Fire-and-forget: SAST/secrets scans below still run
		// independently, so a refresh failure never blocks security
		// coverage.
		if c.graphRefresher != nil {
			repoIDStr, _ := data.Metadata["repository_id"].(string)
			commitSHA, _ := data.Metadata["commit_sha"].(string)
			before, _ := data.Metadata["before"].(string)
			ref, _ := data.Metadata["ref"].(string)
			if repoID, err := uuid.Parse(repoIDStr); err == nil && commitSHA != "" {
				if _, err := c.graphRefresher.HandlePush(ctx, usecase.PushEvent{
					RepoID:    repoID,
					CommitSHA: commitSHA,
					Before:    before,
					Ref:       ref,
				}); err != nil {
					logger.Warn(ctx, "graph refresh failed", "error", err, "repo_id", repoIDStr)
				}
			}
		}

		// Trigger SAST + secrets scan on push
		repo, _ := data.Metadata["repository"].(string)
		branch, _ := data.Metadata["branch"].(string)
		tenantID, _ := uuid.Parse(data.Metadata["organization_id"].(string))

		if repo == "" || tenantID == uuid.Nil {
			return
		}

		logger.Info(ctx, "Git push detected, triggering scan", "repo", repo, "branch", branch)

		// Trigger SAST scan
		_, err := c.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
			TenantID:    tenantID,
			ScanType:    domain.ScanTypeSAST,
			Target:      repo,
			Branch:      branch,
			TriggeredBy: "event:git.push",
		})
		if err != nil {
			logger.Warn(ctx, "Failed to trigger SAST scan from git push", "error", err)
		}

		// Trigger secrets scan
		_, err = c.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
			TenantID:    tenantID,
			ScanType:    domain.ScanTypeSecretDetection,
			Target:      repo,
			Branch:      branch,
			TriggeredBy: "event:git.push",
		})
		if err != nil {
			logger.Warn(ctx, "Failed to trigger secrets scan from git push", "error", err)
		}

	case "sentiae.git.pr.created":
		// Trigger diff-aware scan on PR
		repo, _ := data.Metadata["repository"].(string)
		branch, _ := data.Metadata["head_branch"].(string)
		tenantID, _ := uuid.Parse(data.Metadata["organization_id"].(string))

		if repo == "" || tenantID == uuid.Nil {
			return
		}

		logger.Info(ctx, "PR created, triggering diff-aware scan", "repo", repo, "branch", branch)

		_, err := c.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
			TenantID:    tenantID,
			ScanType:    domain.ScanTypeSAST,
			Target:      repo,
			Branch:      branch,
			TriggeredBy: "event:git.pr.created",
		})
		if err != nil {
			logger.Warn(ctx, "Failed to trigger PR scan", "error", err)
		}
	}
}

func (c *Consumer) handleOpsEvent(ctx context.Context, msg kafka.Message) {
	var event events.CloudEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		logger.Warn(ctx, "Failed to parse ops event", "error", err)
		return
	}

	data, err := parseEventData(event.Data)
	if err != nil {
		logger.Warn(ctx, "Failed to parse ops event data", "error", err)
		return
	}

	if event.Type == "sentiae.ops.deploy.completed" {
		// Trigger container scan for newly deployed image
		image, _ := data.Metadata["image"].(string)
		tenantID, _ := uuid.Parse(data.Metadata["organization_id"].(string))

		if image == "" || tenantID == uuid.Nil {
			return
		}

		logger.Info(ctx, "Deployment completed, triggering container scan", "image", image)

		_, err := c.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
			TenantID:    tenantID,
			ScanType:    domain.ScanTypeContainer,
			Target:      image,
			TriggeredBy: "event:ops.deploy.completed",
		})
		if err != nil {
			logger.Warn(ctx, "Failed to trigger container scan from deployment", "error", err)
		}
	}
}

func (c *Consumer) handleCanvasEvent(ctx context.Context, msg kafka.Message) {
	var event events.CloudEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		logger.Warn(ctx, "Failed to parse canvas event", "error", err)
		return
	}

	data, err := parseEventData(event.Data)
	if err != nil {
		logger.Warn(ctx, "Failed to parse canvas event data", "error", err)
		return
	}

	if event.Type == "sentiae.canvas.node.published" {
		// Trigger SCA scan for published node
		repo, _ := data.Metadata["repository"].(string)
		tenantID, _ := uuid.Parse(data.Metadata["organization_id"].(string))

		if repo == "" || tenantID == uuid.Nil {
			return
		}

		logger.Info(ctx, "Node published, triggering SCA scan", "repo", repo)

		_, err := c.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
			TenantID:    tenantID,
			ScanType:    domain.ScanTypeSCA,
			Target:      repo,
			TriggeredBy: "event:canvas.node.published",
		})
		if err != nil {
			logger.Warn(ctx, "Failed to trigger SCA scan from node publish", "error", err)
		}
	}
}
