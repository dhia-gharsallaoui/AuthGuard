package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"authguard/pkg/concurrency"
)

// ProviderType represents authentication provider types
type ProviderType int

const (
	ProviderTypeUnknown ProviderType = iota
	ProviderTypeFirebase
	ProviderTypeIPWhitelist
)

// String returns the string representation of the provider type
func (p ProviderType) String() string {
	switch p {
	case ProviderTypeFirebase:
		return "firebase"
	case ProviderTypeIPWhitelist:
		return "ip_whitelist"
	default:
		return "unknown"
	}
}

// ParseProviderType parses a string to ProviderType
func ParseProviderType(s string) ProviderType {
	switch s {
	case "firebase":
		return ProviderTypeFirebase
	case "ip_whitelist":
		return ProviderTypeIPWhitelist
	default:
		return ProviderTypeUnknown
	}
}

// AuthContext provides authentication context abstracted from HTTP
type AuthContext struct {
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	Body       io.Reader         `json:"-"` // Don't serialize the reader
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
}

// GetHeader returns a header value (case-insensitive)
func (ac *AuthContext) GetHeader(name string) (string, bool) {
	// Try exact match first
	if value, exists := ac.Headers[name]; exists {
		return value, true
	}

	// Try case-insensitive match
	for key, value := range ac.Headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}

	return "", false
}

// GetCookie returns a cookie value
func (ac *AuthContext) GetCookie(name string) (string, bool) {
	value, exists := ac.Cookies[name]
	return value, exists
}

// ReadBody reads and returns the request body (can only be called once)
func (ac *AuthContext) ReadBody() ([]byte, error) {
	if ac.Body == nil {
		return nil, nil
	}
	return io.ReadAll(ac.Body)
}

// LockManager defines the interface for concurrency control
type LockManager interface {
	// Lock acquires a lock for the given key
	Lock(key string)

	// Unlock releases the lock for the given key
	Unlock(key string)
}

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	// Type returns the provider type
	Type() ProviderType

	// LoadConfig loads and validates provider configuration
	LoadConfig(loader ConfigLoader) error

	// Validate validates authentication context and returns user claims
	// Providers should implement their own caching logic using the injected cache
	// Cache keys should use format: "providername:key" for easy identification
	Validate(ctx context.Context, authCtx *AuthContext) (*UserClaims, error)

	// Health checks the provider's health status
	Health(ctx context.Context) error

	// Close closes the provider and cleans up resources
	Close() error
}

// UserClaims represents the standard user claims from any provider
type UserClaims struct {
	Subject       string         `json:"sub"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Name          string         `json:"name,omitempty"`
	Picture       string         `json:"picture,omitempty"`
	IssuedAt      time.Time      `json:"iat"`
	ExpiresAt     time.Time      `json:"exp"`
	Issuer        string         `json:"iss"`
	Audience      []string       `json:"aud,omitempty"`
	CustomClaims  map[string]any `json:"custom_claims,omitempty"`
	Provider      ProviderType   `json:"provider"`
}

// AuthGuard is the main service struct that manages multiple providers
type AuthGuard struct {
	providers    map[ProviderType]AuthProvider
	cache        Cache
	config       *Config
	configLoader ConfigLoader
	metrics      Metrics
	logger       Logger
	lockManager  LockManager
}

// NewAuthGuard creates a new AuthGuard instance
func NewAuthGuard(config *Config, configLoader ConfigLoader, cache Cache, metrics Metrics, logger Logger) *AuthGuard {
	return &AuthGuard{
		providers:    make(map[ProviderType]AuthProvider),
		cache:        cache,
		config:       config,
		configLoader: configLoader,
		metrics:      metrics,
		logger:       logger,
		lockManager:  concurrency.NewMutexManager(),
	}
}

// RegisterProvider registers a new authentication provider and loads its configuration
func (ag *AuthGuard) RegisterProvider(provider AuthProvider) error {
	// Load the provider's configuration
	if err := provider.LoadConfig(ag.configLoader); err != nil {
		return fmt.Errorf("failed to load config for provider %s: %w", provider.Type(), err)
	}

	ag.providers[provider.Type()] = provider
	ag.logger.Info("registered auth provider", "provider", provider.Type().String())
	return nil
}

// LockManager returns the lock manager instance
func (ag *AuthGuard) LockManager() LockManager {
	return ag.lockManager
}

// ValidateAuth validates authentication using the specified provider
func (ag *AuthGuard) ValidateAuth(ctx context.Context, providerType ProviderType, authCtx *AuthContext) (*UserClaims, error) {
	provider, exists := ag.providers[providerType]
	if !exists {
		ag.metrics.IncValidationAttempts("provider_not_found")
		return nil, ErrProviderNotFound
	}

	start := time.Now()
	claims, err := provider.Validate(ctx, authCtx)
	duration := time.Since(start)

	ag.metrics.ObserveValidationDuration(providerType.String(), duration)

	if err != nil {
		ag.metrics.IncValidationAttempts("failure")

		// Log invalid tokens as debug/warn, not error (they're expected user errors)
		if isUserError(err) {
			ag.logger.Debug("authentication validation failed", "provider", providerType.String(), "error", err)
		} else {
			ag.logger.Error("authentication validation failed", "provider", providerType.String(), "error", err)
		}
		return nil, err
	}

	claims.Provider = providerType
	ag.metrics.IncValidationAttempts("success")
	ag.logger.Debug("authentication validated successfully", "provider", providerType.String(), "subject", claims.Subject)

	return claims, nil
}

// ValidateMultiAuth validates authentication using multiple providers in sequence
// All providers must succeed for the validation to pass
func (ag *AuthGuard) ValidateMultiAuth(ctx context.Context, providerTypes []ProviderType, authCtx *AuthContext) (*UserClaims, error) {
	if len(providerTypes) == 0 {
		return nil, ErrProviderNotFound
	}

	var finalClaims *UserClaims
	var providers []string

	for _, providerType := range providerTypes {
		provider, exists := ag.providers[providerType]
		if !exists {
			ag.metrics.IncValidationAttempts("provider_not_found")
			ag.logger.Error("provider not found in multi-auth", "provider", providerType.String())
			return nil, ErrProviderNotFound
		}

		start := time.Now()
		claims, err := provider.Validate(ctx, authCtx)
		duration := time.Since(start)

		ag.metrics.ObserveValidationDuration(providerType.String(), duration)
		providers = append(providers, providerType.String())

		if err != nil {
			ag.metrics.IncValidationAttempts("failure")

			// Log invalid tokens as debug/warn, not error (they're expected user errors)
			if isUserError(err) {
				ag.logger.Debug("authentication validation failed in multi-auth",
					"provider", providerType.String(),
					"providers", providers,
					"error", err)
			} else {
				ag.logger.Error("authentication validation failed in multi-auth",
					"provider", providerType.String(),
					"providers", providers,
					"error", err)
			}
			return nil, err
		}

		// Merge claims instead of replacing them
		if finalClaims == nil {
			// First provider - use as base
			finalClaims = claims
		} else {
			// Subsequent providers - merge claims
			finalClaims = ag.mergeClaims(finalClaims, claims, providerType)
		}

		ag.logger.Debug("provider validated successfully in multi-auth",
			"provider", providerType.String(),
			"subject", claims.Subject)
	}

	// Set composite provider info
	finalClaims.Provider = providerTypes[0] // Primary provider
	if len(providerTypes) > 1 {
		// Add custom claim indicating all providers used
		if finalClaims.CustomClaims == nil {
			finalClaims.CustomClaims = make(map[string]interface{})
		}
		finalClaims.CustomClaims["auth_providers"] = providers
	}

	ag.metrics.IncValidationAttempts("success")
	ag.logger.Debug("multi-auth validation successful",
		"providers", providers,
		"subject", finalClaims.Subject)

	return finalClaims, nil
}

// Health checks the health of all registered providers
func (ag *AuthGuard) Health(ctx context.Context) map[string]error {
	results := make(map[string]error)
	for providerType, provider := range ag.providers {
		results[providerType.String()] = provider.Health(ctx)
	}
	return results
}

// isUserError determines if an error is a user error (invalid token) vs system error
func isUserError(err error) bool {
	// These are expected user errors that shouldn't be logged as system errors
	return errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrTokenExpired) ||
		errors.Is(err, ErrInvalidIssuer) ||
		errors.Is(err, ErrInvalidAudience) ||
		errors.Is(err, ErrInvalidSigningMethod) ||
		errors.Is(err, ErrMissingKeyID) ||
		errors.Is(err, ErrUnauthorized)
}

// mergeClaims updates baseClaims with non-empty values from newClaims
func (ag *AuthGuard) mergeClaims(baseClaims, newClaims *UserClaims, providerType ProviderType) *UserClaims {
	// Update string fields if they're non-empty
	if newClaims.Subject != "" {
		baseClaims.Subject = newClaims.Subject
	}
	if newClaims.Email != "" {
		baseClaims.Email = newClaims.Email
		baseClaims.EmailVerified = newClaims.EmailVerified
	}
	if newClaims.Name != "" {
		baseClaims.Name = newClaims.Name
	}
	if newClaims.Picture != "" {
		baseClaims.Picture = newClaims.Picture
	}
	if newClaims.Issuer != "" {
		baseClaims.Issuer = newClaims.Issuer
	}

	// Update time fields if they're non-zero
	if !newClaims.IssuedAt.IsZero() {
		baseClaims.IssuedAt = newClaims.IssuedAt
	}
	if !newClaims.ExpiresAt.IsZero() {
		baseClaims.ExpiresAt = newClaims.ExpiresAt
	}

	// Update audience if not empty
	if len(newClaims.Audience) > 0 {
		baseClaims.Audience = newClaims.Audience
	}

	// Merge custom claims
	if newClaims.CustomClaims != nil {
		if baseClaims.CustomClaims == nil {
			baseClaims.CustomClaims = make(map[string]interface{})
		}
		for k, v := range newClaims.CustomClaims {
			baseClaims.CustomClaims[k] = v
		}
	}

	return baseClaims
}

// Close closes all providers and cleans up resources
func (ag *AuthGuard) Close() error {
	ag.logger.Info("closing AuthGuard", "providers_count", len(ag.providers))

	// Close all providers
	for providerType, provider := range ag.providers {
		ag.logger.Debug("closing provider", "provider", providerType)
		if err := provider.Close(); err != nil {
			ag.logger.Error("failed to close provider", "provider", providerType, "error", err)
		} else {
			ag.logger.Debug("provider closed successfully", "provider", providerType)
		}
	}

	// Close cache
	ag.logger.Debug("closing cache")
	if err := ag.cache.Close(); err != nil {
		ag.logger.Error("failed to close cache", "error", err)
		return err
	}
	ag.logger.Debug("cache closed successfully")

	ag.logger.Info("AuthGuard closed successfully")
	return nil
}
