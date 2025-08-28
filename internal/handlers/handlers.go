package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"authguard/internal/auth"
)

// AuthGuardInterface defines the interface for authentication guard operations
type AuthGuardInterface interface {
	ValidateAuth(ctx context.Context, providerType auth.ProviderType, authCtx *auth.AuthContext) (*auth.UserClaims, error)
	ValidateMultiAuth(ctx context.Context, providerTypes []auth.ProviderType, authCtx *auth.AuthContext) (*auth.UserClaims, error)
	Health(ctx context.Context) map[string]error
}

// HealthStatus represents health check status
type HealthStatus int

const (
	HealthStatusHealthy HealthStatus = iota
	HealthStatusUnhealthy
	HealthStatusDegraded
)

// String returns the string representation of the health status
func (h HealthStatus) String() string {
	switch h {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler interface
func (h HealthStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

// Handlers contains all HTTP handlers with shared dependencies
type Handlers struct {
	authGuard AuthGuardInterface
	cache     auth.Cache
	logger    auth.Logger
	metrics   auth.Metrics
}

// NewHandlers creates a new handlers instance with injected dependencies
func NewHandlers(authGuard AuthGuardInterface, cache auth.Cache, logger auth.Logger, metrics auth.Metrics) *Handlers {
	return &Handlers{
		authGuard: authGuard,
		cache:     cache,
		logger:    logger.With("component", "handlers"),
		metrics:   metrics,
	}
}

// ValidateHandler handles POST /validate requests
func (h *Handlers) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Get providers from header or query parameter, defaulting to firebase
	providerTypes := h.parseProviders(r)
	if len(providerTypes) == 0 {
		providerTypes = []auth.ProviderType{auth.ProviderTypeFirebase}
	}

	// Create AuthContext from HTTP request
	authCtx := h.createAuthContext(r)

	var claims *auth.UserClaims
	var err error

	// Use multi-auth if multiple providers specified, otherwise single auth
	if len(providerTypes) > 1 {
		claims, err = h.authGuard.ValidateMultiAuth(r.Context(), providerTypes, authCtx)
	} else {
		claims, err = h.authGuard.ValidateAuth(r.Context(), providerTypes[0], authCtx)
	}

	if err != nil {
		h.logger.Debug("authentication validation failed", "providers", providerTypes, "error", err)

		// Convert domain error to HTTP error
		httpError := auth.ErrorToHTTPError(err)
		statusCode := auth.ErrorToHTTPStatus(err)
		h.writeError(w, httpError, statusCode)
		return
	}

	// Set response headers for nginx
	h.setUserHeaders(w, claims)

	// Success response (nginx auth_request expects 2xx status)
	w.WriteHeader(http.StatusOK)

	duration := time.Since(start)
	h.logger.Debug("authentication validation successful",
		"providers", providerTypes,
		"subject", claims.Subject,
		"duration", duration)
}

// HealthCheckHandler handles GET /health requests
func (h *Handlers) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	response := HealthResponse{
		Timestamp: time.Now(),
		Providers: make(map[string]ProviderHealth),
	}

	// Check providers health
	providerResults := h.authGuard.Health(ctx)
	allHealthy := true

	for name, err := range providerResults {
		providerHealth := ProviderHealth{
			Status: HealthStatusHealthy,
		}

		if err != nil {
			providerHealth.Status = HealthStatusUnhealthy
			providerHealth.Error = err.Error()
			allHealthy = false
		}

		response.Providers[name] = providerHealth
	}

	// Check cache health
	cacheStats := h.cache.Stats()
	response.Cache = CacheHealth{
		Type:   cacheStats.Type,
		Status: HealthStatusHealthy,
		Stats:  cacheStats,
	}

	// Set overall status
	if allHealthy {
		response.Status = HealthStatusHealthy
	} else {
		response.Status = HealthStatusUnhealthy
	}

	// Set response status code
	statusCode := http.StatusOK
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode health response", "error", err)
	}

	h.logger.Debug("health check completed",
		"status", response.Status,
		"providers_count", len(response.Providers))
}

// setUserHeaders sets user information headers for nginx
func (h *Handlers) setUserHeaders(w http.ResponseWriter, claims *auth.UserClaims) {
	// Set standard headers that nginx can use
	w.Header().Set("X-User-ID", claims.Subject)
	w.Header().Set("X-User-Provider", claims.Provider.String())
	w.Header().Set("X-Token-Expires", claims.ExpiresAt.Format(time.RFC3339))

	if claims.Email != "" {
		w.Header().Set("X-User-Email", claims.Email)
	}

	if claims.Name != "" {
		w.Header().Set("X-User-Name", claims.Name)
	}

	if claims.EmailVerified {
		w.Header().Set("X-User-Email-Verified", "true")
	}
}

// parseProviders extracts provider list from header or query parameter
func (h *Handlers) parseProviders(r *http.Request) []auth.ProviderType {
	var providerNames []string

	if providersHeader := r.Header.Get("X-Auth-Providers"); providersHeader != "" {
		providerNames = strings.Split(providersHeader, ",")
	}

	// Parse provider names to types
	var providerTypes []auth.ProviderType
	for _, name := range providerNames {
		name = strings.TrimSpace(name)
		if providerType := auth.ParseProviderType(name); providerType != auth.ProviderTypeUnknown {
			providerTypes = append(providerTypes, providerType)
		} else {
			h.logger.Warn("unknown provider type", "provider", name)
		}
	}

	return providerTypes
}

// createAuthContext creates an AuthContext from HTTP request
func (h *Handlers) createAuthContext(r *http.Request) *auth.AuthContext {
	// Extract headers
	headers := make(map[string]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[name] = values[0] // Use first value
		}
	}

	// Extract cookies
	cookies := make(map[string]string)
	for _, cookie := range r.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	return &auth.AuthContext{
		Headers:    headers,
		Cookies:    cookies,
		Body:       r.Body,
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
	}
}

// writeError writes an error response
func (h *Handlers) writeError(w http.ResponseWriter, httpErr *auth.HTTPError, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(httpErr); err != nil {
		h.logger.Warn("failed to encode error response", "error", err)
	}

	h.logger.Debug("authentication error",
		"code", httpErr.Code,
		"message", httpErr.Message,
		"details", httpErr.Details,
		"status", statusCode)
}

// HealthResponse types
type HealthResponse struct {
	Status    HealthStatus              `json:"status"`
	Timestamp time.Time                 `json:"timestamp"`
	Providers map[string]ProviderHealth `json:"providers"`
	Cache     CacheHealth               `json:"cache"`
}

type ProviderHealth struct {
	Status HealthStatus `json:"status"`
	Error  string       `json:"error,omitempty"`
	Stats  any          `json:"stats,omitempty"`
}

type CacheHealth struct {
	Type   auth.CacheType  `json:"type"`
	Status HealthStatus    `json:"status"`
	Stats  auth.CacheStats `json:"stats"`
}
