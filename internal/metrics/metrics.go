package metrics

import (
	"sync/atomic"
	"time"

	"authguard/internal/auth"
)

// Metrics implements the auth.Metrics interface with in-memory counters
type Metrics struct {
	config auth.MetricsConfig

	// Counters
	validationAttempts int64
	cacheHits          int64
	cacheMisses        int64
	providerErrors     int64
	providerRequests   int64

	// Gauges
	activeConnections int64
	cachedKeys        int64

	// Histograms (simplified - just track totals for now)
	validationDuration time.Duration
	cacheOpDuration    time.Duration
}

// NewMetrics creates a new metrics instance
func NewMetrics(config auth.MetricsConfig) (auth.Metrics, error) {
	return &Metrics{
		config: config,
	}, nil
}

// IncValidationAttempts increments validation attempts counter
func (m *Metrics) IncValidationAttempts(result string) {
	atomic.AddInt64(&m.validationAttempts, 1)
}

// IncCacheHits increments cache hits counter
func (m *Metrics) IncCacheHits(provider string) {
	atomic.AddInt64(&m.cacheHits, 1)
}

// IncCacheMisses increments cache misses counter
func (m *Metrics) IncCacheMisses(provider string) {
	atomic.AddInt64(&m.cacheMisses, 1)
}

// IncProviderErrors increments provider errors counter
func (m *Metrics) IncProviderErrors(provider string, errorType string) {
	atomic.AddInt64(&m.providerErrors, 1)
}

// ObserveValidationDuration records validation duration
func (m *Metrics) ObserveValidationDuration(provider string, duration time.Duration) {
	// Simplified: just store the last duration for now
	m.validationDuration = duration
}

// ObserveCacheOperationDuration records cache operation duration
func (m *Metrics) ObserveCacheOperationDuration(operation string, duration time.Duration) {
	m.cacheOpDuration = duration
}

// SetActiveConnections sets the active connections gauge
func (m *Metrics) SetActiveConnections(count int) {
	atomic.StoreInt64(&m.activeConnections, int64(count))
}

// SetCachedKeys sets the cached keys gauge
func (m *Metrics) SetCachedKeys(provider string, count int) {
	atomic.StoreInt64(&m.cachedKeys, int64(count))
}

// SetProviderStatus sets provider status
func (m *Metrics) SetProviderStatus(provider string, healthy bool) {
	// For now, just log it - could be extended with actual gauge
}

// IncProviderRequests increments provider requests counter
func (m *Metrics) IncProviderRequests(provider string) {
	atomic.AddInt64(&m.providerRequests, 1)
}

// GetStats returns current metrics statistics (for debugging/monitoring)
func (m *Metrics) GetStats() map[string]any {
	return map[string]any{
		"validation_attempts":    atomic.LoadInt64(&m.validationAttempts),
		"cache_hits":             atomic.LoadInt64(&m.cacheHits),
		"cache_misses":           atomic.LoadInt64(&m.cacheMisses),
		"provider_errors":        atomic.LoadInt64(&m.providerErrors),
		"provider_requests":      atomic.LoadInt64(&m.providerRequests),
		"active_connections":     atomic.LoadInt64(&m.activeConnections),
		"cached_keys":            atomic.LoadInt64(&m.cachedKeys),
		"validation_duration_ns": m.validationDuration.Nanoseconds(),
		"cache_op_duration_ns":   m.cacheOpDuration.Nanoseconds(),
	}
}
