package cache

import (
	"fmt"

	"authguard/internal/auth"
)

// NewCache creates a cache based on the provided configuration
// Falls back to memory cache if Redis configuration fails
func NewCache(config auth.CacheConfig, logger auth.Logger) (auth.Cache, error) {
	switch config.Type {
	case auth.CacheTypeRedis:
		return createRedisCache(config, logger)

	case auth.CacheTypeMemory:
		return createMemoryCache(config, logger)

	default:
		logger.Warn("unknown cache type, defaulting to memory", "type", config.Type)
		return createMemoryCache(config, logger)
	}
}

// createRedisCache attempts to create a Redis cache with fallback to memory
func createRedisCache(config auth.CacheConfig, logger auth.Logger) (auth.Cache, error) {
	if config.RedisURL == "" {
		logger.Info("Redis URL not configured, falling back to memory cache")
		return createMemoryCache(config, logger)
	}

	logger.Info("attempting to connect to Redis", "url", config.RedisURL, "db", config.RedisDB)

	redisConfig := RedisCacheConfig{
		Address:      config.RedisURL,
		Password:     config.RedisPassword,
		DB:           config.RedisDB,
		MaxRetries:   3,
		PoolSize:     10,
		MinIdleConns: 5,
	}

	redisCache, err := NewRedisCache(redisConfig)
	if err != nil {
		logger.Warn("failed to connect to Redis, falling back to memory cache", "error", err)
		return createMemoryCache(config, logger)
	}

	logger.Info("Redis cache initialized successfully")
	return redisCache, nil
}

// createMemoryCache creates a memory cache
func createMemoryCache(config auth.CacheConfig, logger auth.Logger) (auth.Cache, error) {
	logger.Info("initializing memory cache",
		"max_keys", config.MaxKeys,
		"cleanup_interval", config.CleanupInterval)

	memoryConfig := MemoryCacheConfig{
		MaxKeys:         config.MaxKeys,
		CleanupInterval: config.CleanupInterval,
	}

	memoryCache, err := NewMemoryCache(memoryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory cache: %w", err)
	}

	logger.Info("memory cache initialized successfully")
	return memoryCache, nil
}
