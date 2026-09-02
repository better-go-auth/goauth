package interfaces

import "context"

// ITransactionManager manages atomic operations across multiple repository calls.
type ITransactionManager interface {
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}
