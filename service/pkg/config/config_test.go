//go:build unit

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// validConfig returns a fully-populated Config equivalent to the shipped
// configs/config.yaml defaults, used as the baseline for negative cases.
func validConfig() Config {
	return Config{
		Server: ServerConfig{
			Port: "8091", GRPCPort: 50054, Environment: "development",
			LogLevel: "info", ReadTimeout: 1, WriteTimeout: 1, IdleTimeout: 1,
		},
		Database: DatabaseConfig{
			Host: "localhost", Port: "5432", User: "postgres", Name: "code_analysis_service",
			SSLMode: "disable", MaxOpenConns: 200, MaxIdleConns: 50, MaxLifetime: 1,
		},
		Redis:     RedisConfig{Addr: "localhost:6379"},
		Telemetry: TelemetryConfig{ServiceName: "vigil-service", OTLPEndpoint: "localhost:4317", MetricPort: "9092"},
	}
}

// TestRealDefaultConfigPasses proves the shipped configs/config.yaml still
// validates after enabling WithRequiredStructEnabled — i.e. no legitimately
// required nested field is actually missing, so the service boots healthy.
func TestRealDefaultConfigPasses(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default config not found at %s: %v", path, err)
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("read default config: %v", err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshal default config: %v", err)
	}

	if err := newValidator().Struct(&cfg); err != nil {
		t.Fatalf("real default config failed validation after flip: %v", err)
	}
}

// TestMissingRequiredNestedStructFails proves a zero-value nested struct that
// carries a `required` tag now fails validation — the exact hole the flip
// closes (previously silently ignored).
func TestMissingRequiredNestedStructFails(t *testing.T) {
	cfg := validConfig()
	cfg.Redis = RedisConfig{} // zero out a `validate:"required"` nested struct

	err := newValidator().Struct(&cfg)
	if err == nil {
		t.Fatal("expected validation to fail for missing required Redis struct, got nil")
	}
	if !strings.Contains(err.Error(), "Redis") {
		t.Fatalf("expected error to mention Redis, got: %v", err)
	}
}

// TestRequiredStructOptionIsEnabled directly demonstrates the option is active:
// a `required` tag on a non-pointer struct field is enforced by newValidator()
// but is a silent no-op under a bare validator.New(). This is the mechanical
// difference #nested-required-tags-silently-ignored is about.
func TestRequiredStructOptionIsEnabled(t *testing.T) {
	// inner carries NO leaf `required` tag, so a bare validator finds nothing to
	// enforce when Nested is the zero struct — the struct-level `required` on
	// Nested is the only control, and it is a no-op without the option.
	type inner struct {
		Field string `validate:"omitempty"`
	}
	type outer struct {
		Nested inner `validate:"required"`
	}
	empty := outer{} // Nested is the zero struct

	if err := validator.New().Struct(&empty); err != nil {
		t.Fatalf("baseline invalid: bare validator must ignore struct-level required here, got: %v", err)
	}

	if err := newValidator().Struct(&empty); err == nil {
		t.Fatal("WithRequiredStructEnabled not active: struct-level required tag was ignored")
	} else if !errors.As(err, new(validator.ValidationErrors)) {
		t.Fatalf("unexpected error type: %v", err)
	}
}
