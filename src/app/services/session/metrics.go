package session

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter("goauth/sessions")
	cacheErrorCounter metric.Int64Counter
)

func init() {
	var err error
	cacheErrorCounter, err = meter.Int64Counter("goauth.sessions.cache_errors",
		metric.WithDescription("Count of secondary-storage cache errors"))
	if err != nil {
		cacheErrorCounter = nil
	}
}

func incCacheError(ctx context.Context) {
	if cacheErrorCounter != nil {
		cacheErrorCounter.Add(ctx, 1)
	}
}
