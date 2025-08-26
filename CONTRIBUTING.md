# Contributing to AuthGuard 🤝

Thank you for your interest in contributing to AuthGuard! This guide will help you get started with development and explain how to create new authentication providers.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Creating New Auth Providers](#creating-new-auth-providers)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)

## Development Setup

### Prerequisites

- **Go 1.24+** - [Install Go](https://golang.org/doc/install)
- **Docker & Docker Compose** - For development dependencies
- **Make** - For build automation
- **Git** - Version control

### Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dhia-gharsallaoui/AuthGuard.git
   cd AuthGuard
   ```

2. **Start development dependencies:**
   ```bash
   make dev-up  # Starts Redis via Docker Compose
   ```

3. **Set up environment:**
   ```bash
   make setup-env  # Creates .env from template
   # Edit .env with your configuration
   ```

4. **Install dependencies:**
   ```bash
   make deps
   ```

5. **Build and run:**
   ```bash
   make build
   make run-env
   ```

### Development Commands

```bash
make help           # Show all available commands
make build          # Build the binary
make run            # Run locally (requires sourced .env)  
make run-env        # Run with environment loaded
make test           # Run all tests
make lint           # Run linter
make format         # Format code
make check          # Run tests + linting
make dev-up         # Start dev dependencies
make dev-down       # Stop dev dependencies
```

## Project Structure

```
auth-nginx/
├── cmd/authguard/              # Application entry point
├── internal/
│   ├── auth/                   # Core authentication interfaces and types
│   │   ├── provider.go         # AuthProvider interface definition
│   │   ├── config.go           # Configuration management
│   │   ├── errors.go           # Common error types
│   │   └── ...
│   ├── cache/                  # Cache implementations (Redis, Memory)
│   ├── config/                 # Application configuration
│   ├── handlers/               # HTTP handlers and server
│   ├── logging/                # Structured logging
│   ├── metrics/                # Prometheus metrics
│   └── providers/              # Authentication provider implementations
│       ├── firebase/           # Firebase Admin SDK provider
│       └── ip_whitelist/       # IP whitelist provider
├── pkg/                        # Reusable packages
├── tests/                      # Integration and E2E tests
├── dev/                        # Development configuration
├── Makefile                    # Build automation
└── docker-compose.yml          # Development environment
```

## Creating New Auth Providers

AuthGuard's strength lies in its **composable authentication architecture**. Adding new providers is straightforward thanks to the clean interface design.

### Provider Interface

Every authentication provider must implement the `AuthProvider` interface:

```go
type AuthProvider interface {
    // Type returns the provider type
    Type() ProviderType

    // LoadConfig loads and validates provider configuration
    LoadConfig(loader ConfigLoader) error

    // Validate validates authentication context and returns user claims
    Validate(ctx context.Context, authCtx *AuthContext) (*UserClaims, error)

    // Health checks the provider's health status
    Health(ctx context.Context) error

    // Close closes the provider and cleans up resources
    Close() error
}
```

### Step-by-Step Guide

#### 1. Define Provider Type

Add your provider type to `internal/auth/provider.go`:

```go
const (
    ProviderTypeUnknown ProviderType = iota
    ProviderTypeFirebase
    ProviderTypeIPWhitelist
    ProviderTypeJWT          // ← Add your provider here
)

// Update String() method
func (p ProviderType) String() string {
    switch p {
    case ProviderTypeFirebase:
        return "firebase"
    case ProviderTypeIPWhitelist:
        return "ip_whitelist"
    case ProviderTypeJWT:
        return "jwt"           // ← Add case here
    default:
        return "unknown"
    }
}

// Update ParseProviderType() method
func ParseProviderType(s string) ProviderType {
    switch s {
    case "firebase":
        return ProviderTypeFirebase
    case "ip_whitelist":
        return ProviderTypeIPWhitelist
    case "jwt":
        return ProviderTypeJWT  // ← Add case here
    default:
        return ProviderTypeUnknown
    }
}
```

#### 2. Create Provider Directory

```bash
mkdir internal/providers/jwt
```

#### 3. Create Configuration

Create `internal/providers/jwt/config.go`:

```go
package jwt

import (
    "authguard/internal/auth"
    "fmt"
)

type Config struct {
    SecretKey    string `env:"JWT_SECRET_KEY" required:"true"`
    Issuer       string `env:"JWT_ISSUER" required:"true"`
    Audience     string `env:"JWT_AUDIENCE"`
    ExpiryBuffer int    `env:"JWT_EXPIRY_BUFFER" default:"300"` // 5 minutes
}

func (c *Config) Validate() error {
    if c.SecretKey == "" {
        return fmt.Errorf("JWT_SECRET_KEY is required")
    }
    if c.Issuer == "" {
        return fmt.Errorf("JWT_ISSUER is required")
    }
    return nil
}
```

#### 4. Create Errors (Optional)

Create `internal/providers/jwt/errors.go`:

```go
package jwt

import "errors"

var (
    ErrInvalidJWTFormat    = errors.New("invalid JWT format")
    ErrInvalidSignature    = errors.New("invalid JWT signature")
    ErrJWTExpired         = errors.New("JWT token has expired")
    ErrInvalidClaims      = errors.New("invalid JWT claims")
)
```

#### 5. Implement Provider

Create `internal/providers/jwt/provider.go`:

```go
package jwt

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    "authguard/internal/auth"
)

type Provider struct {
    config      *Config
    logger      auth.Logger
    metrics     auth.Metrics
    cache       auth.Cache
    lockManager auth.LockManager
}

// NewProvider creates a new JWT authentication provider
func NewProvider(cache auth.Cache, lockManager auth.LockManager, logger auth.Logger, metrics auth.Metrics) *Provider {
    return &Provider{
        logger:      logger.With("provider", "jwt"),
        metrics:     metrics,
        cache:       cache,
        lockManager: lockManager,
    }
}

// Type returns the provider type
func (p *Provider) Type() auth.ProviderType {
    return auth.ProviderTypeJWT
}

// LoadConfig loads and validates JWT configuration
func (p *Provider) LoadConfig(loader auth.ConfigLoader) error {
    config := &Config{}
    
    // Load configuration from environment
    if err := loader.LoadStruct(config); err != nil {
        return fmt.Errorf("failed to load JWT config: %w", err)
    }
    
    // Validate configuration
    if err := config.Validate(); err != nil {
        return fmt.Errorf("invalid JWT config: %w", err)
    }
    
    p.config = config
    p.logger.Info("JWT provider configured", "issuer", config.Issuer)
    return nil
}

// Validate validates JWT token and returns user claims
func (p *Provider) Validate(ctx context.Context, authCtx *auth.AuthContext) (*auth.UserClaims, error) {
    // Get Authorization header
    authHeader, exists := authCtx.GetHeader("Authorization")
    if !exists {
        return nil, auth.ErrMissingToken
    }
    
    // Extract Bearer token
    token := strings.TrimPrefix(authHeader, "Bearer ")
    if token == authHeader {
        return nil, auth.ErrInvalidToken
    }
    
    // Check cache first
    cacheKey := fmt.Sprintf("jwt:%s", hashToken(token))
    if cached, err := p.cache.Get(ctx, cacheKey); err == nil {
        var claims auth.UserClaims
        if err := json.Unmarshal(cached, &claims); err == nil {
            p.metrics.IncCacheHits("jwt")
            return &claims, nil
        }
    }
    p.metrics.IncCacheMisses("jwt")
    
    // Validate JWT token
    claims, err := p.validateJWT(token)
    if err != nil {
        return nil, err
    }
    
    // Cache successful validation
    if claimsData, err := json.Marshal(claims); err == nil {
        ttl := time.Until(claims.ExpiresAt)
        if ttl > 0 {
            _ = p.cache.Set(ctx, cacheKey, claimsData, ttl)
        }
    }
    
    return claims, nil
}

// validateJWT validates the JWT token and extracts claims
func (p *Provider) validateJWT(token string) (*auth.UserClaims, error) {
    // Split token into parts
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return nil, ErrInvalidJWTFormat
    }
    
    header, payload, signature := parts[0], parts[1], parts[2]
    
    // Verify signature
    expectedSignature := p.sign(header + "." + payload)
    if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
        return nil, ErrInvalidSignature
    }
    
    // Decode payload
    payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
    if err != nil {
        return nil, ErrInvalidJWTFormat
    }
    
    // Parse claims
    var jwtClaims struct {
        Sub   string                 `json:"sub"`
        Email string                 `json:"email"`
        Name  string                 `json:"name"`
        Iss   string                 `json:"iss"`
        Aud   string                 `json:"aud"`
        Exp   int64                  `json:"exp"`
        Iat   int64                  `json:"iat"`
        Custom map[string]interface{} `json:"custom,omitempty"`
    }
    
    if err := json.Unmarshal(payloadBytes, &jwtClaims); err != nil {
        return nil, ErrInvalidClaims
    }
    
    // Validate claims
    now := time.Now().Unix()
    if jwtClaims.Exp <= now {
        return nil, ErrJWTExpired
    }
    
    if jwtClaims.Iss != p.config.Issuer {
        return nil, auth.ErrInvalidIssuer
    }
    
    if p.config.Audience != "" && jwtClaims.Aud != p.config.Audience {
        return nil, auth.ErrInvalidAudience
    }
    
    // Convert to standard claims
    claims := &auth.UserClaims{
        Subject:      jwtClaims.Sub,
        Email:        jwtClaims.Email,
        Name:         jwtClaims.Name,
        Issuer:       jwtClaims.Iss,
        Audience:     []string{jwtClaims.Aud},
        IssuedAt:     time.Unix(jwtClaims.Iat, 0),
        ExpiresAt:    time.Unix(jwtClaims.Exp, 0),
        CustomClaims: jwtClaims.Custom,
        Provider:     auth.ProviderTypeJWT,
    }
    
    return claims, nil
}

// sign creates HMAC signature for JWT
func (p *Provider) sign(data string) string {
    h := hmac.New(sha256.New, []byte(p.config.SecretKey))
    h.Write([]byte(data))
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Health checks the provider's health
func (p *Provider) Health(ctx context.Context) error {
    if p.config == nil {
        return fmt.Errorf("JWT provider not configured")
    }
    return nil
}

// Close cleans up resources
func (p *Provider) Close() error {
    p.logger.Debug("JWT provider closed")
    return nil
}

// hashToken creates a hash of the token for cache keys
func hashToken(token string) string {
    h := sha256.New()
    h.Write([]byte(token))
    return fmt.Sprintf("%x", h.Sum(nil))[:16] // First 16 chars
}
```

#### 6. Register Provider

Add your provider to `cmd/authguard/main.go`:

```go
import (
    // ... other imports
    "authguard/internal/providers/jwt"
)

// In the provider registration section:
for _, providerType := range config.Providers {
    switch providerType {
    case auth.ProviderTypeFirebase:
        // ... existing firebase code
    case auth.ProviderTypeIPWhitelist:
        // ... existing ip_whitelist code
    case auth.ProviderTypeJWT:
        provider := jwt.NewProvider(cache, authGuard.LockManager(), logger, metrics)
        if err := authGuard.RegisterProvider(provider); err != nil {
            return fmt.Errorf("failed to register JWT provider: %w", err)
        }
    default:
        return fmt.Errorf("unsupported provider type: %s", providerType)
    }
}
```

#### 7. Add Tests

Create `internal/providers/jwt/provider_test.go`:

```go
package jwt

import (
    "context"
    "testing"
    "time"

    "authguard/internal/auth"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestJWTProvider_Validate(t *testing.T) {
    // Create test provider
    provider := NewProvider(
        &mockCache{},
        &mockLockManager{},
        &mockLogger{},
        &mockMetrics{},
    )
    
    // Load test config
    config := &Config{
        SecretKey: "test-secret-key",
        Issuer:    "test-issuer",
        Audience:  "test-audience",
    }
    provider.config = config
    
    // Test valid token
    validToken := createTestJWT(t, config, map[string]interface{}{
        "sub": "user123",
        "email": "test@example.com",
        "exp": time.Now().Add(time.Hour).Unix(),
    })
    
    authCtx := &auth.AuthContext{
        Headers: map[string]string{
            "Authorization": "Bearer " + validToken,
        },
    }
    
    claims, err := provider.Validate(context.Background(), authCtx)
    require.NoError(t, err)
    assert.Equal(t, "user123", claims.Subject)
    assert.Equal(t, "test@example.com", claims.Email)
}

// Helper function to create test JWT tokens
func createTestJWT(t *testing.T, config *Config, claims map[string]interface{}) string {
    // Implementation depends on your JWT library
    // This is a simplified example
    return "test.jwt.token"
}
```

### Provider Development Best Practices

#### 1. Configuration Management

- Use environment variables with the `env` tag
- Provide sensible defaults
- Validate configuration in `LoadConfig()`
- Log configuration (without secrets)

#### 2. Caching Strategy

- Always implement caching for performance
- Use provider-specific cache keys: `"providername:key"`
- Respect token expiration times for TTL
- Handle cache failures gracefully

#### 3. Error Handling

- Use specific, typed errors
- Distinguish between user errors (invalid tokens) and system errors
- Don't log sensitive information
- Return appropriate HTTP status codes

#### 4. Security Considerations

- Never log tokens or secrets
- Validate all inputs thoroughly
- Use constant-time comparisons for secrets
- Implement proper token validation
- Handle edge cases securely

#### 5. Testing

- Write comprehensive unit tests
- Test both success and failure cases
- Mock external dependencies
- Test configuration validation
- Test error conditions

#### 6. Metrics and Logging

- Use structured logging with the provider context
- Implement relevant metrics (validation attempts, cache hits/misses)
- Log at appropriate levels (DEBUG for success, ERROR for system failures)
- Include relevant context in logs

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test ./internal/providers/jwt/

# Run tests with race detection
go test -race ./...
```

### Test Structure

- **Unit tests:** Test individual functions and methods
- **Integration tests:** Test provider integration with AuthGuard
- **E2E tests:** Test full authentication flows

### Test Helpers

Use the provided test helpers in `internal/auth/testing/`:

```go
// Mock implementations for testing
type mockCache struct{}
type mockLogger struct{}
type mockMetrics struct{}
```

## Code Style

### Go Standards

- Follow standard Go conventions
- Use `gofmt` and `go vet`
- Use meaningful variable names
- Add comments for exported functions
- Handle errors appropriately

### Formatting

```bash
make format  # Runs gofmt on all files
make lint    # Runs golangci-lint
```

### Code Organization

- Keep files focused and cohesive
- Separate concerns (config, errors, implementation)
- Use interfaces for testability
- Follow the existing project structure

## Submitting Changes

### Before Submitting

1. **Run tests:** `make check`
2. **Update documentation:** Update README if needed
3. **Test manually:** Verify your changes work end-to-end
4. **Check dependencies:** Ensure no unnecessary dependencies

### Commit Guidelines

- Write clear, concise commit messages
- Use conventional commit format if possible
- Include tests with new features
- Update documentation for new providers

### Pull Request Process

1. **Fork the repository**
2. **Create a feature branch:** `git checkout -b feature/jwt-provider`
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request** with:
   - Clear description of changes
   - Test results
   - Documentation updates
   - Example usage

### Example Provider PR Checklist

- [ ] Provider implements all `AuthProvider` interface methods
- [ ] Configuration is environment-variable driven
- [ ] Comprehensive tests included
- [ ] Error handling follows project patterns
- [ ] Caching implemented appropriately
- [ ] Logging and metrics integrated
- [ ] Documentation updated
- [ ] Examples provided

## Getting Help

- **Issues:** Open an issue on GitHub
- **Discussions:** Use GitHub Discussions for questions
- **Documentation:** Check the README and code comments

## Examples

### Real-World Provider Examples

Look at existing providers for reference:

- **Firebase Provider:** `internal/providers/firebase/` - JWT validation with external service
- **IP Whitelist Provider:** `internal/providers/ip_whitelist/` - Network-based authentication

### Provider Composition

Your new provider can be composed with existing ones:

```nginx
# JWT + IP whitelist for admin endpoints
proxy_set_header X-Auth-Providers "jwt,ip_whitelist";

# Just JWT for API endpoints  
proxy_set_header X-Auth-Providers "jwt";

# Firebase + JWT for migration scenarios
proxy_set_header X-Auth-Providers "firebase,jwt";
```

This composable design makes AuthGuard incredibly flexible for complex authentication requirements.

---

Thank you for contributing to AuthGuard! Your new authentication providers help make the system more versatile and useful for everyone. 🚀
