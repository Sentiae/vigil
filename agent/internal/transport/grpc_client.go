package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sentiae/vigil/agent/internal/ebpf"
)

// ControlPlaneClient communicates with the vigil-service control plane.
// Uses HTTP/JSON for registration and heartbeat (gRPC will be added when proto is generated).
type ControlPlaneClient struct {
	baseURL    string
	agentID    string
	httpClient *http.Client
}

func NewControlPlaneClient(baseURL string) *ControlPlaneClient {
	return &ControlPlaneClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Register registers this agent with the control plane.
func (c *ControlPlaneClient) Register(ctx context.Context, bootstrapToken, hostname, agentType, version, kernelVersion string, btfSupported bool) (string, error) {
	payload := map[string]any{
		"bootstrap_token": bootstrapToken,
		"hostname":        hostname,
		"agent_type":      agentType,
		"version":         version,
		"kernel_version":  kernelVersion,
		"btf_supported":   btfSupported,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/security/agents/register", body)
	if err != nil {
		return "", fmt.Errorf("register: %w", err)
	}

	var result struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}

	c.agentID = result.AgentID
	slog.Info("Agent registered with control plane", "agent_id", c.agentID)
	return c.agentID, nil
}

// Heartbeat sends a health status to the control plane.
func (c *ControlPlaneClient) Heartbeat(ctx context.Context, cpu, mem float64, eventsProcessed int64) error {
	payload := map[string]any{
		"agent_id":         c.agentID,
		"cpu_usage_pct":    cpu,
		"memory_usage_pct": mem,
		"events_processed": eventsProcessed,
		"timestamp":        time.Now().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = c.doRequest(ctx, "POST", "/api/v1/security/agents/heartbeat", body)
	return err
}

// SendEvents sends a batch of events to the control plane.
func (c *ControlPlaneClient) SendEvents(ctx context.Context, events []ebpf.Event) error {
	payload := map[string]any{
		"agent_id": c.agentID,
		"events":   events,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = c.doRequest(ctx, "POST", "/api/v1/security/agents/events", body)
	return err
}

func (c *ControlPlaneClient) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if body != nil {
		req.Body = http.NoBody // Will be replaced below
		// Use proper body
		req, err = http.NewRequestWithContext(ctx, method, url, bytesReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("control plane returned %d", resp.StatusCode)
	}

	var result []byte
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	return result, nil
}

type bytesReaderType struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReaderType {
	return &bytesReaderType{data: data}
}

func (r *bytesReaderType) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
