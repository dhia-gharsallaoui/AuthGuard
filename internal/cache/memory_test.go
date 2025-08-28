package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"authguard/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type MemoryCacheTestSuite struct {
	suite.Suite
	cache *MemoryCache
	ctx   context.Context
}

func (suite *MemoryCacheTestSuite) SetupTest() {
	config := MemoryCacheConfig{
		MaxKeys:         10,
		CleanupInterval: 100 * time.Millisecond, // Short interval for testing
	}

	var err error
	suite.cache, err = NewMemoryCache(config)
	assert.NoError(suite.T(), err)
	suite.ctx = context.Background()
}

func (suite *MemoryCacheTestSuite) TearDownTest() {
	if suite.cache != nil {
		_ = suite.cache.Close()
	}
}

func (suite *MemoryCacheTestSuite) TestNewMemoryCache() {
	// Test with default values
	config := MemoryCacheConfig{}
	cache, err := NewMemoryCache(config)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), cache)
	assert.Equal(suite.T(), 1000, cache.maxKeys)
	assert.Equal(suite.T(), 10*time.Minute, cache.janitor.interval)

	_ = cache.Close()
}

func (suite *MemoryCacheTestSuite) TestNewMemoryCache_WithConfig() {
	config := MemoryCacheConfig{
		MaxKeys:         500,
		CleanupInterval: 5 * time.Minute,
	}
	cache, err := NewMemoryCache(config)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), cache)
	assert.Equal(suite.T(), 500, cache.maxKeys)
	assert.Equal(suite.T(), 5*time.Minute, cache.janitor.interval)

	_ = cache.Close()
}

func (suite *MemoryCacheTestSuite) TestSetAndGet() {
	key := "test-key"
	value := []byte("test-value")

	// Set value
	err := suite.cache.Set(suite.ctx, key, value, 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Get value
	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), value, retrieved)
}

func (suite *MemoryCacheTestSuite) TestGet_KeyNotFound() {
	key := "nonexistent-key"

	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), auth.ErrCacheKeyNotFound, err)
	assert.Nil(suite.T(), retrieved)
}

func (suite *MemoryCacheTestSuite) TestSetWithTTL_Expiration() {
	key := "expire-key"
	value := []byte("expire-value")

	// Set with very short TTL
	err := suite.cache.Set(suite.ctx, key, value, 50*time.Millisecond)
	assert.NoError(suite.T(), err)

	// Should exist immediately
	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), value, retrieved)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	expiredValue, expiredErr := suite.cache.Get(suite.ctx, key)
	assert.Error(suite.T(), expiredErr)
	assert.Equal(suite.T(), auth.ErrCacheKeyNotFound, expiredErr)
	assert.Nil(suite.T(), expiredValue)
}

func (suite *MemoryCacheTestSuite) TestSetWithZeroTTL() {
	key := "no-expire-key"
	value := []byte("no-expire-value")

	// Set with zero TTL (no expiration)
	err := suite.cache.Set(suite.ctx, key, value, 0)
	assert.NoError(suite.T(), err)

	// Should exist
	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), value, retrieved)

	// Should still exist after some time
	time.Sleep(50 * time.Millisecond)
	persistentValue, persistentErr := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), persistentErr)
	assert.Equal(suite.T(), value, persistentValue)
}

func (suite *MemoryCacheTestSuite) TestDelete() {
	key := "delete-key"
	value := []byte("delete-value")

	// Set value
	err := suite.cache.Set(suite.ctx, key, value, 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Verify it exists
	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), value, retrieved)

	// Delete it
	err = suite.cache.Delete(suite.ctx, key)
	assert.NoError(suite.T(), err)

	// Should not exist anymore
	deletedValue, deletedErr := suite.cache.Get(suite.ctx, key)
	assert.Error(suite.T(), deletedErr)
	assert.Equal(suite.T(), auth.ErrCacheKeyNotFound, deletedErr)
	assert.Nil(suite.T(), deletedValue)
}

func (suite *MemoryCacheTestSuite) TestDelete_NonExistentKey() {
	key := "nonexistent-key"

	// Delete non-existent key should not error
	err := suite.cache.Delete(suite.ctx, key)
	assert.NoError(suite.T(), err)
}

func (suite *MemoryCacheTestSuite) TestExists() {
	key := "exist-key"
	value := []byte("exist-value")

	// Should not exist initially
	exists := suite.cache.Exists(suite.ctx, key)
	assert.False(suite.T(), exists)

	// Set value
	err := suite.cache.Set(suite.ctx, key, value, 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Should exist now
	exists = suite.cache.Exists(suite.ctx, key)
	assert.True(suite.T(), exists)

	// Delete it
	err = suite.cache.Delete(suite.ctx, key)
	assert.NoError(suite.T(), err)

	// Should not exist anymore
	exists = suite.cache.Exists(suite.ctx, key)
	assert.False(suite.T(), exists)
}

func (suite *MemoryCacheTestSuite) TestExists_ExpiredKey() {
	key := "expire-exist-key"
	value := []byte("expire-exist-value")

	// Set with short TTL
	err := suite.cache.Set(suite.ctx, key, value, 50*time.Millisecond)
	assert.NoError(suite.T(), err)

	// Should exist initially
	exists := suite.cache.Exists(suite.ctx, key)
	assert.True(suite.T(), exists)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should not exist after expiration
	exists = suite.cache.Exists(suite.ctx, key)
	assert.False(suite.T(), exists)
}

func (suite *MemoryCacheTestSuite) TestMaxKeysEviction() {
	// Create cache with max 3 keys
	config := MemoryCacheConfig{
		MaxKeys:         3,
		CleanupInterval: 1 * time.Hour, // Long interval to avoid cleanup during test
	}
	cache, err := NewMemoryCache(config)
	assert.NoError(suite.T(), err)
	defer func() { _ = cache.Close() }()

	// Add 3 keys
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := cache.Set(suite.ctx, key, value, 1*time.Hour)
		assert.NoError(suite.T(), err)
	}

	// All 3 should exist
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		exists := cache.Exists(suite.ctx, key)
		assert.True(suite.T(), exists)
	}

	// Add 4th key, should evict one
	err = cache.Set(suite.ctx, "key-3", []byte("value-3"), 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Should have exactly 3 keys
	stats := cache.Stats()
	assert.Equal(suite.T(), int64(3), stats.Keys)
}

func (suite *MemoryCacheTestSuite) TestUpdateExistingKey() {
	key := "update-key"
	value1 := []byte("value1")
	value2 := []byte("value2")

	// Set initial value
	err := suite.cache.Set(suite.ctx, key, value1, 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Get initial stats
	initialStats := suite.cache.Stats()

	// Update with new value
	err = suite.cache.Set(suite.ctx, key, value2, 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Key count should not increase
	newStats := suite.cache.Stats()
	assert.Equal(suite.T(), initialStats.Keys, newStats.Keys)

	// Should get new value
	retrieved, err := suite.cache.Get(suite.ctx, key)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), value2, retrieved)
}

func (suite *MemoryCacheTestSuite) TestStats() {
	// Initial stats
	stats := suite.cache.Stats()
	assert.Equal(suite.T(), auth.CacheTypeMemory, stats.Type)
	assert.Equal(suite.T(), int64(0), stats.Keys)
	assert.Equal(suite.T(), int64(0), stats.Hits)
	assert.Equal(suite.T(), int64(0), stats.Misses)

	// Add some keys
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("stats-key-%d", i)
		value := []byte(fmt.Sprintf("stats-value-%d", i))
		err := suite.cache.Set(suite.ctx, key, value, 1*time.Hour)
		assert.NoError(suite.T(), err)
	}

	// Get some keys (hits)
	_, _ = suite.cache.Get(suite.ctx, "stats-key-0")
	_, _ = suite.cache.Get(suite.ctx, "stats-key-1")

	// Try to get non-existent key (miss)
	_, _ = suite.cache.Get(suite.ctx, "nonexistent")

	// Check updated stats
	stats = suite.cache.Stats()
	assert.Equal(suite.T(), int64(3), stats.Keys)
	assert.Equal(suite.T(), int64(2), stats.Hits)
	assert.Equal(suite.T(), int64(1), stats.Misses)
}

func (suite *MemoryCacheTestSuite) TestCleanup() {
	// Create cache with very short cleanup interval
	config := MemoryCacheConfig{
		MaxKeys:         100,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache, err := NewMemoryCache(config)
	assert.NoError(suite.T(), err)
	defer func() { _ = cache.Close() }()

	// Add keys with different expiration times
	err = cache.Set(suite.ctx, "short-lived", []byte("value1"), 25*time.Millisecond)
	assert.NoError(suite.T(), err)

	err = cache.Set(suite.ctx, "long-lived", []byte("value2"), 200*time.Millisecond)
	assert.NoError(suite.T(), err)

	// Both should exist initially
	assert.True(suite.T(), cache.Exists(suite.ctx, "short-lived"))
	assert.True(suite.T(), cache.Exists(suite.ctx, "long-lived"))

	// Wait for cleanup to run (should clean expired keys)
	time.Sleep(100 * time.Millisecond)

	// Short-lived should be cleaned up, long-lived should remain
	assert.False(suite.T(), cache.Exists(suite.ctx, "short-lived"))
	assert.True(suite.T(), cache.Exists(suite.ctx, "long-lived"))
}

func (suite *MemoryCacheTestSuite) TestClose() {
	// Create a new cache for this test
	config := MemoryCacheConfig{
		MaxKeys:         10,
		CleanupInterval: 100 * time.Millisecond,
	}
	cache, err := NewMemoryCache(config)
	assert.NoError(suite.T(), err)

	// Add some data
	err = cache.Set(suite.ctx, "test-key", []byte("test-value"), 1*time.Hour)
	assert.NoError(suite.T(), err)

	// Close should not error
	err = cache.Close()
	assert.NoError(suite.T(), err)

	// Calling close again should not error
	err = cache.Close()
	assert.NoError(suite.T(), err)
}

func TestMemoryCacheTestSuite(t *testing.T) {
	suite.Run(t, new(MemoryCacheTestSuite))
}

// Additional unit tests not in the suite

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	config := MemoryCacheConfig{
		MaxKeys:         100,
		CleanupInterval: 1 * time.Hour,
	}
	cache, err := NewMemoryCache(config)
	assert.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Test concurrent reads and writes
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 50; i++ {
			key := fmt.Sprintf("concurrent-key-%d", i%10)
			value := []byte(fmt.Sprintf("concurrent-value-%d", i))
			_ = cache.Set(ctx, key, value, 1*time.Hour)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 50; i++ {
			key := fmt.Sprintf("concurrent-key-%d", i%10)
			_, _ = cache.Get(ctx, key)
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Should not panic and cache should be functional
	stats := cache.Stats()
	assert.True(t, stats.Keys <= 10)
}

func TestMemoryCache_EdgeCases(t *testing.T) {
	config := MemoryCacheConfig{
		MaxKeys:         2,
		CleanupInterval: 1 * time.Hour,
	}
	cache, err := NewMemoryCache(config)
	assert.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Test empty key
	err = cache.Set(ctx, "", []byte("empty-key-value"), 1*time.Hour)
	assert.NoError(t, err)

	value, err := cache.Get(ctx, "")
	assert.NoError(t, err)
	assert.Equal(t, []byte("empty-key-value"), value)

	// Test empty value
	err = cache.Set(ctx, "empty-value", []byte{}, 1*time.Hour)
	assert.NoError(t, err)

	value, err = cache.Get(ctx, "empty-value")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, value)

	// Test nil value
	err = cache.Set(ctx, "nil-value", nil, 1*time.Hour)
	assert.NoError(t, err)

	value, err = cache.Get(ctx, "nil-value")
	assert.NoError(t, err)
	assert.Nil(t, value)
}
