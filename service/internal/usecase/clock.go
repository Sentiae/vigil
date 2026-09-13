package usecase

import "time"

// Clock abstracts time so use cases stay deterministic in tests (CLAUDE.md §30
// #6 — no time.Now() in use cases).
type Clock interface {
	Now() time.Time
}

// systemClock is the production Clock.
type systemClock struct{}

// NewSystemClock returns a Clock backed by time.Now().UTC().
func NewSystemClock() Clock { return systemClock{} }

func (systemClock) Now() time.Time { return time.Now().UTC() }
