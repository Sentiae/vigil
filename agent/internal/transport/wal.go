package transport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sentiae/vigil/agent/internal/ebpf"
)

// WAL (Write-Ahead Log) provides local event buffering for offline resilience.
// When the gRPC connection to the control plane is down, events are written
// to disk and replayed when connectivity is restored.
type WAL struct {
	mu      sync.Mutex
	dir     string
	file    *os.File
	encoder *json.Encoder
	count   int64
}

func NewWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create WAL dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("wal-%s.jsonl", time.Now().Format("20060102-150405")))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return nil, fmt.Errorf("open WAL file: %w", err)
	}

	return &WAL{
		dir:     dir,
		file:    file,
		encoder: json.NewEncoder(file),
	}, nil
}

// Write appends an event to the WAL.
func (w *WAL) Write(event ebpf.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.encoder.Encode(event); err != nil {
		return fmt.Errorf("encode WAL event: %w", err)
	}
	w.count++
	return nil
}

// Count returns the number of events written to this WAL segment.
func (w *WAL) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Replay reads all events from WAL files in the directory and sends them to the channel.
func (w *WAL) Replay(events chan<- ebpf.Event) (int64, error) {
	files, err := filepath.Glob(filepath.Join(w.dir, "wal-*.jsonl"))
	if err != nil {
		return 0, err
	}

	var total int64
	for _, f := range files {
		data, err := os.Open(f)
		if err != nil {
			continue
		}
		decoder := json.NewDecoder(data)
		for decoder.More() {
			var event ebpf.Event
			if err := decoder.Decode(&event); err != nil {
				break
			}
			events <- event
			total++
		}
		data.Close()
		// Remove replayed WAL file
		os.Remove(f)
	}

	return total, nil
}

// Close flushes and closes the WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
