// Package migrations embeds the Atlas SQL migration files into the binary so the
// boot-time runner needs no filesystem layout at runtime — the Docker image
// carries the schema with the code that expects it (mirrors sibling services).
package migrations

import "embed"

// FS holds every NNNN_*.sql migration (Atlas single-file format, applied in
// ascending filename order).
//
//go:embed *.sql
var FS embed.FS
