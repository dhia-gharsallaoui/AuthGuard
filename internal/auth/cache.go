package auth

import (
	"context"
	"time"
)

// CacheType represents cache implementation types
type CacheType int

const (
	CacheTypeMemory CacheType = iota
	CacheTypeRedis
)

// String returns the string representation of the cache type
func (c CacheType) String() string {
	switch c {
	case CacheTypeMemory:
		return "memory"
	case CacheTypeRedis:
		return "redis"
	default:
		return "memory"
	}
}

// ParseCacheType parses a string to CacheType
func ParseCacheType(s string) CacheType {
	switch s {
	case "memory":
		return CacheTypeMemory
	case "redis":
		return CacheTypeRedis
	default:
		return CacheTypeMemory
	}
}

// Cache defines the interface for key-value storage with TTL support
type Cache interface {
	// Get retrieves a value by key. Returns ErrCacheKeyNotFound if key doesn't exist
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with TTL. TTL of 0 means no expiration
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a key from cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists without retrieving the value
	Exists(ctx context.Context, key string) bool

	// Close closes the cache connection and cleans up resources
	Close() error

	// Stats returns cache statistics for monitoring
	Stats() CacheStats
}

// CacheStats represents cache performance statistics
type CacheStats struct {
	Hits        int64     `json:"hits"`
	Misses      int64     `json:"misses"`
	Keys        int64     `json:"keys"`
	LastUpdated time.Time `json:"last_updated"`
	Type        CacheType `json:"type"`
}
