package auth

import (
	"errors"
	"fmt"
	"net/http"
)

// Domain-level authentication errors (no HTTP status codes)
var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrInvalidIssuer        = errors.New("invalid issuer")
	ErrInvalidAudience      = errors.New("invalid audience")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrMissingKeyID         = errors.New("missing key ID in token header")
	ErrProviderNotFound     = errors.New("authentication provider not found")
	ErrCacheKeyNotFound     = errors.New("cache key not found")
	ErrKeyNotFound          = errors.New("key not found")
	ErrFailedKeyFetch       = errors.New("failed to fetch public keys")
	ErrProviderUnavailable  = errors.New("authentication provider unavailable")
	ErrConfigurationError   = errors.New("configuration error")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
	ErrMissingProjectID     = errors.New("project ID is required")
	ErrInvalidKeyFormat     = errors.New("invalid key format")
	ErrNoValidKeys          = errors.New("no valid keys available")
	ErrCircuitBreakerOpen   = errors.New("circuit breaker is open")
)

// HTTPError provides structured error information for HTTP responses
type HTTPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *HTTPError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

// ErrorToHTTPStatus maps domain errors to HTTP status codes
func ErrorToHTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrTokenExpired),
		errors.Is(err, ErrInvalidIssuer),
		errors.Is(err, ErrInvalidAudience),
		errors.Is(err, ErrInvalidSigningMethod),
		errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized

	case errors.Is(err, ErrProviderNotFound):
		return http.StatusBadRequest

	case errors.Is(err, ErrProviderUnavailable),
		errors.Is(err, ErrFailedKeyFetch),
		errors.Is(err, ErrNoValidKeys),
		errors.Is(err, ErrCircuitBreakerOpen):
		return http.StatusServiceUnavailable

	case errors.Is(err, ErrConfigurationError),
		errors.Is(err, ErrMissingProjectID):
		return http.StatusInternalServerError

	case errors.Is(err, ErrRateLimitExceeded):
		return http.StatusTooManyRequests

	default:
		return http.StatusInternalServerError
	}
}

// ErrorToHTTPError converts domain errors to structured HTTP errors
func ErrorToHTTPError(err error) *HTTPError {
	switch {
	case errors.Is(err, ErrInvalidToken):
		return &HTTPError{Code: "INVALID_TOKEN", Message: "Invalid authentication token"}
	case errors.Is(err, ErrTokenExpired):
		return &HTTPError{Code: "TOKEN_EXPIRED", Message: "Authentication token has expired"}
	case errors.Is(err, ErrInvalidIssuer):
		return &HTTPError{Code: "INVALID_ISSUER", Message: "Token issuer is invalid"}
	case errors.Is(err, ErrInvalidAudience):
		return &HTTPError{Code: "INVALID_AUDIENCE", Message: "Token audience is invalid"}
	case errors.Is(err, ErrUnauthorized):
		return &HTTPError{Code: "UNAUTHORIZED", Message: "Access denied"}
	case errors.Is(err, ErrProviderNotFound):
		return &HTTPError{Code: "PROVIDER_NOT_FOUND", Message: "Authentication provider not found"}
	case errors.Is(err, ErrProviderUnavailable):
		return &HTTPError{Code: "PROVIDER_UNAVAILABLE", Message: "Authentication provider is currently unavailable"}
	case errors.Is(err, ErrRateLimitExceeded):
		return &HTTPError{Code: "RATE_LIMIT_EXCEEDED", Message: "Request rate limit exceeded"}
	case errors.Is(err, ErrConfigurationError):
		return &HTTPError{Code: "CONFIGURATION_ERROR", Message: "Service configuration error"}
	default:
		return &HTTPError{Code: "INTERNAL_ERROR", Message: "Internal authentication error", Details: err.Error()}
	}
}

// WithDetails adds details to an HTTP error
func (e *HTTPError) WithDetails(details string) *HTTPError {
	e.Details = details
	return e
}
