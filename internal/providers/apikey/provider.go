package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"authguard/internal/auth"
)

// Provider implements the AuthProvider interface for API key authentication
type Provider struct {
	config      *Config
	logger      auth.Logger
	metrics     auth.Metrics
	cache       auth.Cache
	lockManager auth.LockManager
}

// NewProvider creates a new API key authentication provider
func NewProvider(cache auth.Cache, lockManager auth.LockManager, logger auth.Logger, metrics auth.Metrics) *Provider {
	return &Provider{
		logger:      logger.With("provider", "api_key"),
		metrics:     metrics,
		cache:       cache,
		lockManager: lockManager,
	}
}

// Type returns the provider type
func (p *Provider) Type() auth.ProviderType {
	return auth.ProviderTypeAPIKey
}

// LoadConfig loads and validates API key configuration
func (p *Provider) LoadConfig(loader auth.ConfigLoader) error {
	config := &Config{
		APIKeys: make(map[string]APIKeyInfo),
	}

	// Load header name (default: "X-API-Key")
	config.HeaderName = loader.GetWithDefault("api_key.header_name", "X-API-Key")

	// Load API keys from string format
	keysStr := loader.GetWithDefault("api_key.keys", "")
	if keysStr != "" {
		keys, err := ParseAPIKeysFromString(keysStr)
		if err != nil {
			return fmt.Errorf("failed to parse API keys: %w", err)
		}
		config.APIKeys = keys
	}

	// Load API keys from JSON format (alternative)
	keysJSON := loader.GetWithDefault("api_key.keys_json", "")
	if keysJSON != "" {
		var keys map[string]APIKeyInfo
		if err := json.Unmarshal([]byte(keysJSON), &keys); err != nil {
			return fmt.Errorf("failed to parse API keys JSON: %w", err)
		}
		// Merge with existing keys
		maps.Copy(config.APIKeys, keys)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("api_key config validation failed: %w", err)
	}

	p.config = config
	p.logger.Info("api_key provider configured",
		"keys_count", len(config.APIKeys),
		"header_name", config.HeaderName)

	return nil
}

// Validate validates API key authentication from AuthContext and returns user claims
func (p *Provider) Validate(ctx context.Context, authCtx *auth.AuthContext) (*auth.UserClaims, error) {
	start := time.Now()
	defer func() {
		p.metrics.ObserveValidationDuration("api_key", time.Since(start))
	}()

	p.metrics.IncProviderRequests("api_key")

	// Extract API key from headers or query parameters
	apiKey, source, err := p.extractAPIKey(authCtx)
	if err != nil {
		return nil, err
	}

	// Generate cache key
	cacheKey := p.generateCacheKey(apiKey)

	// Use lock to prevent concurrent validation of the same key
	p.lockManager.Lock(cacheKey)
	defer p.lockManager.Unlock(cacheKey)

	// Check cache first
	if cachedClaims := p.getCachedClaims(ctx, cacheKey); cachedClaims != nil {
		p.logger.Debug("cache hit for API key validation", "source", source, "subject", cachedClaims.Subject)
		return cachedClaims, nil
	}

	// Validate API key against configuration
	keyInfo, exists := p.config.GetAPIKeyInfo(apiKey)
	if !exists {
		p.logger.Debug("API key not found", "source", source)
		return nil, auth.ErrUnauthorized
	}

	// Convert to UserClaims
	userClaims := p.convertToUserClaims(keyInfo, source)

	// Cache the successful result (API keys don't expire by default)
	p.setCachedClaims(ctx, cacheKey, userClaims)

	p.logger.Debug("API key validated successfully and cached",
		"source", source,
		"subject", userClaims.Subject)

	return userClaims, nil
}

// extractAPIKey extracts the API key from headers
func (p *Provider) extractAPIKey(authCtx *auth.AuthContext) (string, string, error) {
	// Try header first
	if apiKey, ok := authCtx.GetHeader(p.config.HeaderName); ok && apiKey != "" {
		return strings.TrimSpace(apiKey), "header", nil
	}

	// Try Authorization header with "Bearer" prefix as fallback
	if authHeader, ok := authCtx.GetHeader("Authorization"); ok {
		const bearerPrefix = "Bearer "
		if len(authHeader) > len(bearerPrefix) && strings.HasPrefix(authHeader, bearerPrefix) {
			apiKey := strings.TrimSpace(authHeader[len(bearerPrefix):])
			if apiKey != "" {
				return apiKey, "authorization_header", nil
			}
		}
	}

	return "", "", auth.ErrUnauthorized
}

// generateCacheKey creates a cache key for API keys using format "api_key:key_hash"
func (p *Provider) generateCacheKey(apiKey string) string {
	hasher := sha256.New()
	hasher.Write([]byte(apiKey))
	return "api_key:" + hex.EncodeToString(hasher.Sum(nil))[:16] // Use first 16 chars for shorter keys
}

// getCachedClaims retrieves cached claims if available
func (p *Provider) getCachedClaims(ctx context.Context, cacheKey string) *auth.UserClaims {
	data, err := p.cache.Get(ctx, cacheKey)
	if err != nil {
		if !errors.Is(err, auth.ErrCacheKeyNotFound) {
			p.logger.Debug("cache get error", "key", cacheKey, "error", err)
		}
		return nil
	}

	var claims auth.UserClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		p.logger.Debug("cache unmarshal error", "key", cacheKey, "error", err)
		return nil
	}

	return &claims
}

// setCachedClaims stores authentication claims in cache
func (p *Provider) setCachedClaims(ctx context.Context, cacheKey string, claims *auth.UserClaims) {
	data, err := json.Marshal(claims)
	if err != nil {
		p.logger.Debug("cache marshal error", "key", cacheKey, "error", err)
		return
	}

	// API keys don't expire, so use a long TTL (24 hours)
	ttl := 24 * time.Hour

	if err := p.cache.Set(ctx, cacheKey, data, ttl); err != nil {
		p.logger.Debug("cache set error", "key", cacheKey, "error", err)
	} else {
		p.logger.Debug("cached API key validation result", "key", cacheKey, "ttl", ttl)
	}
}

// convertToUserClaims converts API key info to UserClaims
func (p *Provider) convertToUserClaims(keyInfo APIKeyInfo, source string) *auth.UserClaims {
	now := time.Now()

	claims := &auth.UserClaims{
		Subject:      keyInfo.UserID,
		Email:        keyInfo.Email,
		Name:         keyInfo.Name,
		Provider:     auth.ProviderTypeAPIKey,
		IssuedAt:     now,
		ExpiresAt:    time.Time{}, // API keys don't expire by default
		Issuer:       "authguard-api-key",
		CustomClaims: make(map[string]any),
	}

	// Add custom claims from config
	if keyInfo.CustomClaims != nil {
		maps.Copy(claims.CustomClaims, keyInfo.CustomClaims)
	}

	// Add API key specific claims
	claims.CustomClaims["api_key_source"] = source
	if keyInfo.IsAdmin {
		claims.CustomClaims["is_admin"] = true
	}

	return claims
}

// Health checks the API key provider's health
func (p *Provider) Health(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("api_key provider not configured")
	}

	if len(p.config.APIKeys) == 0 {
		return fmt.Errorf("no API keys configured")
	}

	return nil
}

// Close closes the provider and cleans up resources
func (p *Provider) Close() error {
	// No resources to clean up
	return nil
}

// Stats returns API key provider statistics
func (p *Provider) Stats() any {
	if p.config == nil {
		return map[string]any{
			"status": "not_configured",
		}
	}

	return map[string]any{
		"keys_count":  len(p.config.APIKeys),
		"header_name": p.config.HeaderName,
	}
}
