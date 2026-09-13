package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/port/repository"
)

// txCtxKey is the private context key under which txManager stashes the active
// pgx transaction for dbFrom to pick up.
type txCtxKey struct{}

// querier is the statement surface shared by *pgxpool.Pool and pgx.Tx, so a
// repository method runs unchanged inside or outside a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type txManager struct {
	pool *pgxpool.Pool
}

// NewTxManager returns the pgx implementation of repository.TransactionManager.
func NewTxManager(pool *pgxpool.Pool) repository.TransactionManager {
	return &txManager{pool: pool}
}

var _ repository.TransactionManager = (*txManager)(nil)

// WithTransaction begins a transaction, runs fn with a context carrying it, and
// commits when fn returns nil; any error (or panic) rolls it back.
func (m *txManager) WithTransaction(ctx context.Context, fn func(txCtx context.Context) error) error {
	return pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
		return fn(context.WithValue(ctx, txCtxKey{}, tx))
	})
}

// dbFrom returns the transaction carried on ctx, or the pool when there is none.
func dbFrom(ctx context.Context, pool *pgxpool.Pool) querier {
	if tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}
