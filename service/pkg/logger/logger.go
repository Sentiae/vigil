package logger

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel/trace"
)

var (
	Log *slog.Logger
)

type TraceHandler struct {
	slog.Handler
}

func (h TraceHandler) Handle(ctx context.Context, r slog.Record) error {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		r.AddAttrs(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

func Init(level string, extra ...slog.Handler) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	// Base JSON handler
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)

	// Wrap with TraceHandler
	var handler slog.Handler = TraceHandler{Handler: jsonHandler}

	// Fan the decorated handler and any extra handlers (e.g. the OTLP slog
	// bridge from platform-kit/otel) into one, so stdout and the collector see
	// the same record.
	if len(extra) > 0 {
		handler = teeHandler{handlers: append([]slog.Handler{handler}, extra...)}
	}

	Log = slog.New(handler)
	slog.SetDefault(Log)
}

// teeHandler fans one record out to every underlying handler: Enabled is the OR
// of the children, Handle dispatches a clone to each enabled child, and
// WithAttrs/WithGroup map over all. The clone keeps one child's mutations (the
// TraceHandler adds trace attrs) from leaking into another.
type teeHandler struct {
	handlers []slog.Handler
}

func (t teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range t.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return teeHandler{handlers: next}
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		next[i] = h.WithGroup(name)
	}
	return teeHandler{handlers: next}
}

func logger() *slog.Logger {
	if Log != nil {
		return Log
	}
	return slog.Default()
}

func Info(ctx context.Context, msg string, args ...any) {
	logger().InfoContext(ctx, msg, args...)
}

func Error(ctx context.Context, msg string, args ...any) {
	logger().ErrorContext(ctx, msg, args...)
}

func Warn(ctx context.Context, msg string, args ...any) {
	logger().WarnContext(ctx, msg, args...)
}

func Debug(ctx context.Context, msg string, args ...any) {
	logger().DebugContext(ctx, msg, args...)
}
