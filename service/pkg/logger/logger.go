package logger

import (
	"context"
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

func Init(level string) {
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

	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	handler := TraceHandler{Handler: jsonHandler}

	Log = slog.New(handler)
	slog.SetDefault(Log)
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
