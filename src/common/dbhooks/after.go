package dbhooks

import (
	"context"
	"sync"

	"github.com/better-go-auth/goauth/src/common/interfaces"
)

// afterQueueKey marks a context running inside a transaction whose after hooks wait for the commit.
type afterQueueKey struct{}

// afterQueue collects after hooks until the outermost transaction ends (better-auth's
// queueAfterTransactionHook).
type afterQueue struct {
	mu  sync.Mutex
	fns []func(ctx context.Context) error
}

// WithAfterQueue returns a context in which after hooks are queued instead of run, and the function that
// ends the queue: with commit true it runs the queued hooks with ctx (outside the transaction) and returns
// the first error; with commit false it drops them. When ctx already queues (a nested transaction) the
// returned function does nothing and the outer transaction runs the hooks.
func WithAfterQueue(ctx context.Context) (context.Context, func(ctx context.Context, commit bool) error) {
	if _, ok := ctx.Value(afterQueueKey{}).(*afterQueue); ok {
		return ctx, func(context.Context, bool) error { return nil }
	}
	q := &afterQueue{}
	return context.WithValue(ctx, afterQueueKey{}, q), func(ctx context.Context, commit bool) error {
		// Step 1: take the queued hooks
		q.mu.Lock()
		fns := q.fns
		q.fns = nil
		q.mu.Unlock()
		if !commit {
			return nil
		}
		// Step 2: run them in order after the commit; every hook runs, the first error is returned
		var first error
		for _, fn := range fns {
			if err := fn(ctx); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
}

// runOrQueue runs fn now, or queues it when ctx is inside a transaction started by a wrapped
// transaction manager (WrapTx).
func runOrQueue(ctx context.Context, fn func(ctx context.Context) error) error {
	if q, ok := ctx.Value(afterQueueKey{}).(*afterQueue); ok {
		q.mu.Lock()
		q.fns = append(q.fns, fn)
		q.mu.Unlock()
		return nil
	}
	return fn(ctx)
}

// txManager runs after hooks once the outermost transaction committed.
type txManager struct {
	inner interfaces.ITransactionManager
}

// WrapTx returns a transaction manager whose transactions queue database after hooks until they commit
// (dropped on rollback), like better-auth's runWithTransaction. nil stays nil.
func WrapTx(tx interfaces.ITransactionManager) interfaces.ITransactionManager {
	if tx == nil {
		return nil
	}
	if _, ok := tx.(*txManager); ok {
		return tx
	}
	return &txManager{inner: tx}
}

// Transaction implements interfaces.ITransactionManager.
func (t *txManager) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	// Step 1: queue after hooks for the duration of the transaction
	qctx, end := WithAfterQueue(ctx)
	// Step 2: run the transaction
	err := t.inner.Transaction(qctx, fn)
	// Step 3: run the queued hooks after the commit (outside the transaction), drop them on rollback
	if hookErr := end(ctx, err == nil); err == nil {
		err = hookErr
	}
	return err
}
