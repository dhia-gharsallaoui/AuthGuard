package auth

import "time"

// Metrics interface for monitoring and observability
type Metrics interface {
	// Counter metrics
	IncValidationAttempts(result string) // result: "success", "failure", "provider_not_found"
	IncCacheHits(provider string)
	IncCacheMisses(provider string)
	IncProviderErrors(provider string, errorType string)

	// Histogram metrics
	ObserveValidationDuration(provider string, duration time.Duration)
	ObserveCacheOperationDuration(operation string, duration time.Duration)

	// Gauge metrics
	SetActiveConnections(count int)
	SetCachedKeys(provider string, count int)

	// Provider-specific metrics
	SetProviderStatus(provider string, healthy bool)
	IncProviderRequests(provider string)
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" default:"true"`
	Path    string `yaml:"path" default:"/metrics"`
	Port    string `yaml:"port" default:"9090"`
}
