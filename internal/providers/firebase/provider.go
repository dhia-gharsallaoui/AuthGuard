package firebase

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"authguard/internal/auth"

	firebase "firebase.google.com/go/v4"
	firebaseAuth "firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// Provider implements the AuthProvider interface for Firebase using Admin SDK
type Provider struct {
	config      *Config
	authClient  *firebaseAuth.Client
	app         *firebase.App
	logger      auth.Logger
	metrics     auth.Metrics
	cache       auth.Cache
	lockManager auth.LockManager
}

// NewProvider creates a new Firebase authentication provider
func NewProvider(cache auth.Cache, lockManager auth.LockManager, logger auth.Logger, metrics auth.Metrics) *Provider {
	return &Provider{
		logger:      logger.With("provider", "firebase"),
		metrics:     metrics,
		cache:       cache,
		lockManager: lockManager,
	}
}

// Type returns the provider type
func (p *Provider) Type() auth.ProviderType {
	return auth.ProviderTypeFirebase
}

// LoadConfig loads and validates Firebase configuration
func (p *Provider) LoadConfig(loader auth.ConfigLoader) error {
	config := &Config{}

	// Load optional configuration
	config.ProjectID = loader.GetWithDefault("firebase.project_id", "")
	config.CredentialsPath = loader.GetWithDefault("firebase.credentials_path", "")
	config.CredentialsBase64 = loader.GetWithDefault("firebase.credentials_base64", "")

	// Extract project_id from credentials if not provided
	if config.ProjectID == "" && config.CredentialsBase64 != "" {
		if extractedProjectID, err := p.extractProjectIDFromCredentials(config.CredentialsBase64); err == nil {
			config.ProjectID = extractedProjectID
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("firebase config validation failed: %w", err)
	}

	p.config = config

	// Initialize Firebase app
	if err := p.initializeFirebase(); err != nil {
		return fmt.Errorf("failed to initialize Firebase: %w", err)
	}

	p.logger.Info("firebase provider configured", "project_id", config.ProjectID)
	return nil
}

// initializeFirebase initializes the Firebase app and auth client
func (p *Provider) initializeFirebase() error {
	var opts []option.ClientOption

	// Use base64 credentials if provided (for production deployment)
	if p.config.CredentialsBase64 != "" {
		credentialsJSON, err := base64.StdEncoding.DecodeString(p.config.CredentialsBase64)
		if err != nil {
			return fmt.Errorf("failed to decode Firebase credentials: %w", err)
		}
		opts = append(opts, option.WithCredentialsJSON(credentialsJSON))
	} else if p.config.CredentialsPath != "" {
		// Use credentials file path (for local development)
		opts = append(opts, option.WithCredentialsFile(p.config.CredentialsPath))
	}
	// If no credentials provided, Firebase will use default credentials from environment
	// This will use GOOGLE_APPLICATION_CREDENTIALS env var

	// Initialize Firebase app
	firebaseConfig := &firebase.Config{
		ProjectID: p.config.ProjectID,
	}

	app, err := firebase.NewApp(context.Background(), firebaseConfig, opts...)
	if err != nil {
		return fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	// Get Auth client
	authClient, err := app.Auth(context.Background())
	if err != nil {
		return fmt.Errorf("failed to initialize Firebase Auth client: %w", err)
	}

	p.app = app
	p.authClient = authClient

	return nil
}

// extractProjectIDFromCredentials extracts project_id from base64 encoded credentials JSON
func (p *Provider) extractProjectIDFromCredentials(credentialsBase64 string) (string, error) {
	credentialsJSON, err := base64.StdEncoding.DecodeString(credentialsBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode Firebase credentials: %w", err)
	}

	var credentials struct {
		ProjectID string `json:"project_id"`
	}

	if err := json.Unmarshal(credentialsJSON, &credentials); err != nil {
		return "", fmt.Errorf("failed to parse Firebase credentials JSON: %w", err)
	}

	if credentials.ProjectID == "" {
		return "", fmt.Errorf("project_id not found in Firebase credentials")
	}

	return credentials.ProjectID, nil
}

// Validate validates Firebase authentication from AuthContext and returns user claims
func (p *Provider) Validate(ctx context.Context, authCtx *auth.AuthContext) (*auth.UserClaims, error) {
	start := time.Now()
	defer func() {
		p.metrics.ObserveValidationDuration("firebase", time.Since(start))
	}()

	p.metrics.IncProviderRequests("firebase")

	// Extract Bearer token from Authorization header
	authHeader, ok := authCtx.GetHeader("Authorization")
	if !ok {
		return nil, auth.ErrInvalidToken
	}

	// Parse "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return nil, auth.ErrInvalidToken
	}

	tokenString := authHeader[len(bearerPrefix):]
	if tokenString == "" {
		return nil, auth.ErrInvalidToken
	}

	// Generate cache key for this token
	cacheKey := p.generateCacheKey(tokenString)

	// Use lock to prevent concurrent validation of the same token
	p.lockManager.Lock(cacheKey)
	defer p.lockManager.Unlock(cacheKey)

	// Check cache first
	if cachedClaims := p.getCachedClaims(ctx, cacheKey); cachedClaims != nil {
		p.logger.Debug("cache hit for token validation", "subject", cachedClaims.Subject)
		return cachedClaims, nil
	}

	// Verify the token using Firebase Admin SDK
	token, err := p.authClient.VerifyIDToken(ctx, tokenString)
	if err != nil {
		p.logger.Debug("token verification failed", "error", err)
		return nil, p.mapFirebaseError(err)
	}

	// Convert Firebase token to our UserClaims format
	userClaims, err := p.convertTokenToClaims(token)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}

	// Cache the successful result
	p.setCachedClaims(ctx, cacheKey, userClaims)
	p.logger.Debug("token validated successfully and cached", "subject", userClaims.Subject)
	return userClaims, nil
}

// generateCacheKey creates a cache key for Firebase tokens using format "firebase:token_hash"
func (p *Provider) generateCacheKey(tokenString string) string {
	hasher := sha256.New()
	hasher.Write([]byte(tokenString))
	return "firebase:" + hex.EncodeToString(hasher.Sum(nil))[:16] // Use first 16 chars for shorter keys
}

// getCachedClaims retrieves cached claims if available and valid
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

	// Check if claims are expired
	if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
		p.logger.Debug("cached claims expired", "key", cacheKey, "expires_at", claims.ExpiresAt)
		// Delete expired entry async
		go func() {
			_ = p.cache.Delete(context.Background(), cacheKey)
		}()
		return nil
	}

	return &claims
}

// setCachedClaims stores authentication claims in cache with appropriate TTL
func (p *Provider) setCachedClaims(ctx context.Context, cacheKey string, claims *auth.UserClaims) {
	data, err := json.Marshal(claims)
	if err != nil {
		p.logger.Debug("cache marshal error", "key", cacheKey, "error", err)
		return
	}

	// Calculate TTL based on token expiration (Firebase tokens usually expire in 1 hour)
	ttl := time.Hour // Default Firebase ID token TTL
	if !claims.ExpiresAt.IsZero() {
		tokenTTL := time.Until(claims.ExpiresAt)
		if tokenTTL > 0 && tokenTTL < ttl {
			ttl = tokenTTL
		}
	}

	if err := p.cache.Set(ctx, cacheKey, data, ttl); err != nil {
		p.logger.Debug("cache set error", "key", cacheKey, "error", err)
	} else {
		p.logger.Debug("cached token validation result", "key", cacheKey, "ttl", ttl)
	}
}

// mapFirebaseError maps Firebase SDK errors to our auth errors
func (p *Provider) mapFirebaseError(err error) error {
	// Firebase errors are already specific, but we can map them to our domain errors
	errStr := err.Error()

	if contains(errStr, "expired") {
		return auth.ErrTokenExpired
	}
	if contains(errStr, "invalid") || contains(errStr, "malformed") {
		return auth.ErrInvalidToken
	}
	if contains(errStr, "issuer") {
		return auth.ErrInvalidIssuer
	}
	if contains(errStr, "audience") {
		return auth.ErrInvalidAudience
	}

	// Default to invalid token for Firebase errors
	return auth.ErrInvalidToken
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsInMiddle(s, substr))))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// convertTokenToClaims converts Firebase token to our UserClaims format
func (p *Provider) convertTokenToClaims(token *firebaseAuth.Token) (*auth.UserClaims, error) {
	userClaims := &auth.UserClaims{
		Subject:   token.UID,
		Provider:  auth.ProviderTypeFirebase,
		IssuedAt:  time.Unix(token.IssuedAt, 0),
		ExpiresAt: time.Unix(token.Expires, 0),
		Issuer:    token.Issuer,
		Audience:  []string{token.Audience},
	}

	// Extract standard claims
	if email, ok := p.getStringClaim(token.Claims, "email"); ok {
		userClaims.Email = email
	}

	if emailVerified, ok := p.getBoolClaim(token.Claims, "email_verified"); ok {
		userClaims.EmailVerified = emailVerified
	}

	if name, ok := p.getStringClaim(token.Claims, "name"); ok {
		userClaims.Name = name
	}

	if picture, ok := p.getStringClaim(token.Claims, "picture"); ok {
		userClaims.Picture = picture
	}

	// Custom claims (Firebase custom claims are in the root level)
	userClaims.CustomClaims = make(map[string]interface{})
	standardClaims := map[string]bool{
		"iss": true, "aud": true, "exp": true, "iat": true, "sub": true,
		"auth_time": true, "email": true, "email_verified": true,
		"name": true, "picture": true, "firebase": true,
		"phone_number": true,
	}

	for key, value := range token.Claims {
		if !standardClaims[key] {
			userClaims.CustomClaims[key] = value
		}
	}

	return userClaims, nil
}

// getStringClaim safely extracts a string claim
func (p *Provider) getStringClaim(claims map[string]interface{}, key string) (string, bool) {
	if value, exists := claims[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue, true
		}
	}
	return "", false
}

// getBoolClaim safely extracts a boolean claim
func (p *Provider) getBoolClaim(claims map[string]interface{}, key string) (bool, bool) {
	if value, exists := claims[key]; exists {
		if boolValue, ok := value.(bool); ok {
			return boolValue, true
		}
	}
	return false, false
}

// Health checks the Firebase provider's health
func (p *Provider) Health(ctx context.Context) error {
	if p.authClient == nil {
		return fmt.Errorf("firebase auth client not initialized")
	}

	// We can't directly health check Firebase, but we can verify our client is initialized
	// In a real implementation, you might want to make a lightweight test call
	return nil
}

// Close closes the provider and cleans up resources
func (p *Provider) Close() error {
	// Firebase SDK doesn't require explicit cleanup
	return nil
}

// Stats returns Firebase provider statistics
func (p *Provider) Stats() interface{} {
	stats := map[string]interface{}{
		"config": map[string]interface{}{
			"project_id": p.config.ProjectID,
		},
	}

	if p.config.CredentialsPath != "" {
		stats["config"].(map[string]interface{})["credentials_source"] = "file"
	} else if p.config.CredentialsBase64 != "" {
		stats["config"].(map[string]interface{})["credentials_source"] = "base64"
	} else {
		stats["config"].(map[string]interface{})["credentials_source"] = "default"
	}

	return stats
}
