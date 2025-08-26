package cache

import (
	"context"
	"fmt"
	"time"

	"authguard/internal/auth"
	"github.com/redis/go-redis/v9"
)

// RedisCache implements the Cache interface using Redis
type RedisCache struct {
	client *redis.Client
	stats  auth.CacheStats
}

// RedisCacheConfig represents Redis cache configuration
type RedisCacheConfig struct {
	Address      string `yaml:"address" default:"localhost:6379"`
	Password     string `yaml:"password"`
	DB           int    `yaml:"db" default:"0"`
	MaxRetries   int    `yaml:"max_retries" default:"3"`
	PoolSize     int    `yaml:"pool_size" default:"10"`
	MinIdleConns int    `yaml:"min_idle_conns" default:"5"`
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(config RedisCacheConfig) (*RedisCache, error) {
	// Parse Redis URL
	opt, err := redis.ParseURL(config.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Override with config values
	if config.Password != "" {
		opt.Password = config.Password
	}
	opt.DB = config.DB
	opt.MaxRetries = config.MaxRetries
	opt.PoolSize = config.PoolSize
	opt.MinIdleConns = config.MinIdleConns

	// Create Redis client
	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{
		client: client,
		stats: auth.CacheStats{
			Type:        auth.CacheTypeRedis,
			LastUpdated: time.Now(),
		},
	}, nil
}

// Get retrieves a value by key
func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		// Check if it's a "key not found" error
		if err == redis.Nil {
			c.stats.Misses++
			return nil, auth.ErrCacheKeyNotFound
		}
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	c.stats.Hits++
	return []byte(value), nil
}

// Set stores a value with TTL
func (c *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	err := c.client.Set(ctx, key, string(value), ttl).Err()
	if err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	c.stats.LastUpdated = time.Now()
	return nil
}

// Delete removes a key from cache
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("redis delete failed: %w", err)
	}

	c.stats.LastUpdated = time.Now()
	return nil
}

// Exists checks if a key exists
func (c *RedisCache) Exists(ctx context.Context, key string) bool {
	count, err := c.client.Exists(ctx, key).Result()
	return err == nil && count > 0
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Stats returns cache statistics
func (c *RedisCache) Stats() auth.CacheStats {
	// Get current key count from Redis
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := c.stats
	if keys, err := c.client.DBSize(ctx).Result(); err == nil {
		stats.Keys = keys
	}

	return stats
}
