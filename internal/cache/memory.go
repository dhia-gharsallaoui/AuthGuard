package cache

import (
	"context"
	"sync"
	"time"

	"authguard/internal/auth"
)

// MemoryCache implements the Cache interface using in-memory storage
type MemoryCache struct {
	data     map[string]cacheEntry
	mutex    sync.RWMutex
	maxKeys  int
	stats    auth.CacheStats
	janitor  *janitor
	stopChan chan struct{}
}

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

type janitor struct {
	interval time.Duration
	stop     chan bool
}

// MemoryCacheConfig represents configuration for in-memory cache
type MemoryCacheConfig struct {
	MaxKeys         int           `yaml:"max_keys" default:"1000"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" default:"10m"`
}

// NewMemoryCache creates a new in-memory cache instance
func NewMemoryCache(config MemoryCacheConfig) (*MemoryCache, error) {
	if config.MaxKeys <= 0 {
		config.MaxKeys = 1000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 10 * time.Minute
	}

	cache := &MemoryCache{
		data:     make(map[string]cacheEntry),
		maxKeys:  config.MaxKeys,
		stopChan: make(chan struct{}),
		stats: auth.CacheStats{
			Type:        auth.CacheTypeMemory,
			LastUpdated: time.Now(),
		},
	}

	// Start background cleanup
	cache.janitor = &janitor{
		interval: config.CleanupInterval,
		stop:     make(chan bool),
	}
	go cache.runCleanup()

	return cache, nil
}

// Get retrieves a value by key
func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		c.stats.Misses++
		return nil, auth.ErrCacheKeyNotFound
	}

	// Check expiration
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.data, key)
		c.stats.Keys--
		c.mutex.Unlock()
		c.mutex.RLock()
		c.stats.Misses++
		return nil, auth.ErrCacheKeyNotFound
	}

	c.stats.Hits++
	return entry.value, nil
}

// Set stores a value with TTL
func (c *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if we need to evict due to max keys limit
	if len(c.data) >= c.maxKeys {
		if _, exists := c.data[key]; !exists {
			// Remove oldest key (simple FIFO for now)
			for k := range c.data {
				delete(c.data, k)
				c.stats.Keys--
				break
			}
		}
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	wasNew := false
	if _, exists := c.data[key]; !exists {
		wasNew = true
	}

	c.data[key] = cacheEntry{
		value:     value,
		expiresAt: expiresAt,
	}

	if wasNew {
		c.stats.Keys++
	}
	c.stats.LastUpdated = time.Now()

	return nil
}

// Delete removes a key from cache
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.data[key]; exists {
		delete(c.data, key)
		c.stats.Keys--
		c.stats.LastUpdated = time.Now()
	}

	return nil
}

// Exists checks if a key exists
func (c *MemoryCache) Exists(ctx context.Context, key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return false
	}

	// Check expiration
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return false
	}

	return true
}

// Close closes the cache and cleans up resources
func (c *MemoryCache) Close() error {
	// Close the stop channel to signal shutdown
	select {
	case <-c.stopChan:
		// Already closed
	default:
		close(c.stopChan)
	}

	// Try to send stop signal to janitor, but don't block
	if c.janitor != nil {
		select {
		case c.janitor.stop <- true:
			// Successfully sent stop signal
		default:
			// Janitor already stopped, no need to block
		}
	}

	return nil
}

// Stats returns cache statistics
func (c *MemoryCache) Stats() auth.CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stats := c.stats
	stats.Keys = int64(len(c.data))
	return stats
}

// runCleanup runs periodic cleanup of expired entries
func (c *MemoryCache) runCleanup() {
	ticker := time.NewTicker(c.janitor.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.janitor.stop:
			return
		case <-c.stopChan:
			return
		}
	}
}

// cleanup removes expired entries
func (c *MemoryCache) cleanup() {
	now := time.Now()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for key, entry := range c.data {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(c.data, key)
			c.stats.Keys--
		}
	}

	c.stats.LastUpdated = now
}
