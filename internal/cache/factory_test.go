package cache

import (
	"testing"
	"time"

	"authguard/internal/auth"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Debug(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Error(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Warn(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) With(keysAndValues ...any) auth.Logger {
	args := m.Called(keysAndValues)
	return args.Get(0).(auth.Logger)
}

func TestNewCache(t *testing.T) {
	t.Run("Memory cache type", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "initializing memory cache", "max_keys", 1000, "cleanup_interval", 10*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			Type:            auth.CacheTypeMemory,
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := NewCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Verify it's a memory cache
		memCache, ok := cache.(*MemoryCache)
		assert.True(t, ok)
		assert.Equal(t, 1000, memCache.maxKeys)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Redis cache type with empty URL", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "Redis URL not configured, falling back to memory cache")
		mockLogger.On("Info", "initializing memory cache", "max_keys", 500, "cleanup_interval", 5*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			Type:            auth.CacheTypeRedis,
			RedisURL:        "", // Empty URL should fallback to memory
			MaxKeys:         500,
			CleanupInterval: 5 * time.Minute,
		}

		cache, err := NewCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should fallback to memory cache
		_, ok := cache.(*MemoryCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Redis cache type with invalid URL", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "attempting to connect to Redis", "url", "invalid-redis-url", "db", 0)
		mockLogger.On("Warn", "failed to connect to Redis, falling back to memory cache", "error", mock.AnythingOfType("*fmt.wrapError"))
		mockLogger.On("Info", "initializing memory cache", "max_keys", 1000, "cleanup_interval", 10*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			Type:            auth.CacheTypeRedis,
			RedisURL:        "invalid-redis-url",
			RedisPassword:   "password",
			RedisDB:         0,
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := NewCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should fallback to memory cache due to connection failure
		_, ok := cache.(*MemoryCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Unknown cache type", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Warn", "unknown cache type, defaulting to memory", "type", auth.CacheType(999))
		mockLogger.On("Info", "initializing memory cache", "max_keys", 1000, "cleanup_interval", 10*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			Type:            auth.CacheType(999), // Invalid cache type
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := NewCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should default to memory cache
		_, ok := cache.(*MemoryCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})
}

func TestCreateRedisCache(t *testing.T) {
	t.Run("Empty Redis URL", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "Redis URL not configured, falling back to memory cache")
		mockLogger.On("Info", "initializing memory cache", "max_keys", 1000, "cleanup_interval", 10*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			RedisURL:        "",
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := createRedisCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should be memory cache
		_, ok := cache.(*MemoryCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Invalid Redis URL", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "attempting to connect to Redis", "url", "invalid-url", "db", 0)
		mockLogger.On("Warn", "failed to connect to Redis, falling back to memory cache", "error", mock.AnythingOfType("*fmt.wrapError"))
		mockLogger.On("Info", "initializing memory cache", "max_keys", 1000, "cleanup_interval", 10*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			RedisURL:        "invalid-url",
			RedisPassword:   "test",
			RedisDB:         0,
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := createRedisCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should fallback to memory cache
		_, ok := cache.(*MemoryCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Successful Redis connection", func(t *testing.T) {
		// Use miniredis for real Redis connection test
		s := miniredis.RunT(t)
		defer s.Close()

		mockLogger := &MockLogger{}
		mockLogger.On("Info", "attempting to connect to Redis", "url", "redis://"+s.Addr(), "db", 0)
		mockLogger.On("Info", "Redis cache initialized successfully")

		config := auth.CacheConfig{
			RedisURL:        "redis://" + s.Addr(),
			RedisPassword:   "",
			RedisDB:         0,
			MaxKeys:         1000,
			CleanupInterval: 10 * time.Minute,
		}

		cache, err := createRedisCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		// Should be Redis cache, not memory fallback
		_, ok := cache.(*RedisCache)
		assert.True(t, ok)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})
}

func TestCreateMemoryCache(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "initializing memory cache", "max_keys", 500, "cleanup_interval", 5*time.Minute)
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			MaxKeys:         500,
			CleanupInterval: 5 * time.Minute,
		}

		cache, err := createMemoryCache(config, mockLogger)

		assert.NoError(t, err)
		assert.NotNil(t, cache)

		memCache, ok := cache.(*MemoryCache)
		assert.True(t, ok)
		assert.Equal(t, 500, memCache.maxKeys)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})

	t.Run("Invalid memory cache config", func(t *testing.T) {
		mockLogger := &MockLogger{}
		mockLogger.On("Info", "initializing memory cache", "max_keys", -100, "cleanup_interval", time.Duration(-1))
		mockLogger.On("Info", "memory cache initialized successfully")

		config := auth.CacheConfig{
			MaxKeys:         -100,              // Invalid
			CleanupInterval: time.Duration(-1), // Invalid
		}

		cache, err := createMemoryCache(config, mockLogger)

		// Should still work due to defaults in NewMemoryCache
		assert.NoError(t, err)
		assert.NotNil(t, cache)

		memCache, ok := cache.(*MemoryCache)
		assert.True(t, ok)
		// Should use defaults
		assert.Equal(t, 1000, memCache.maxKeys)
		assert.Equal(t, 10*time.Minute, memCache.janitor.interval)

		_ = cache.Close()
		mockLogger.AssertExpectations(t)
	})
}
