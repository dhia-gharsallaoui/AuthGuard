package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorToHTTPStatus(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		// 401 Unauthorized errors
		{
			name:           "Invalid token",
			err:            ErrInvalidToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Token expired",
			err:            ErrTokenExpired,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid issuer",
			err:            ErrInvalidIssuer,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid audience",
			err:            ErrInvalidAudience,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid signing method",
			err:            ErrInvalidSigningMethod,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Missing key ID",
			err:            ErrMissingKeyID,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Unauthorized",
			err:            ErrUnauthorized,
			expectedStatus: http.StatusUnauthorized,
		},
		// 400 Bad Request errors
		{
			name:           "Provider not found",
			err:            ErrProviderNotFound,
			expectedStatus: http.StatusBadRequest,
		},
		// 503 Service Unavailable errors
		{
			name:           "Provider unavailable",
			err:            ErrProviderUnavailable,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "Failed key fetch",
			err:            ErrFailedKeyFetch,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "No valid keys",
			err:            ErrNoValidKeys,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "Circuit breaker open",
			err:            ErrCircuitBreakerOpen,
			expectedStatus: http.StatusServiceUnavailable,
		},
		// 500 Internal Server Error
		{
			name:           "Configuration error",
			err:            ErrConfigurationError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Missing project ID",
			err:            ErrMissingProjectID,
			expectedStatus: http.StatusInternalServerError,
		},
		// 429 Too Many Requests
		{
			name:           "Rate limit exceeded",
			err:            ErrRateLimitExceeded,
			expectedStatus: http.StatusTooManyRequests,
		},
		// Default case (500)
		{
			name:           "Unknown error",
			err:            errors.New("unknown error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ErrorToHTTPStatus(tt.err)
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestErrorToHTTPError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode string
		expectedMsg  string
	}{
		{
			name:         "Invalid token",
			err:          ErrInvalidToken,
			expectedCode: "INVALID_TOKEN",
			expectedMsg:  "Invalid authentication token",
		},
		{
			name:         "Token expired",
			err:          ErrTokenExpired,
			expectedCode: "TOKEN_EXPIRED",
			expectedMsg:  "Authentication token has expired",
		},
		{
			name:         "Invalid issuer",
			err:          ErrInvalidIssuer,
			expectedCode: "INVALID_ISSUER",
			expectedMsg:  "Token issuer is invalid",
		},
		{
			name:         "Invalid audience",
			err:          ErrInvalidAudience,
			expectedCode: "INVALID_AUDIENCE",
			expectedMsg:  "Token audience is invalid",
		},
		{
			name:         "Unauthorized",
			err:          ErrUnauthorized,
			expectedCode: "UNAUTHORIZED",
			expectedMsg:  "Access denied",
		},
		{
			name:         "Provider not found",
			err:          ErrProviderNotFound,
			expectedCode: "PROVIDER_NOT_FOUND",
			expectedMsg:  "Authentication provider not found",
		},
		{
			name:         "Provider unavailable",
			err:          ErrProviderUnavailable,
			expectedCode: "PROVIDER_UNAVAILABLE",
			expectedMsg:  "Authentication provider is currently unavailable",
		},
		{
			name:         "Rate limit exceeded",
			err:          ErrRateLimitExceeded,
			expectedCode: "RATE_LIMIT_EXCEEDED",
			expectedMsg:  "Request rate limit exceeded",
		},
		{
			name:         "Configuration error",
			err:          ErrConfigurationError,
			expectedCode: "CONFIGURATION_ERROR",
			expectedMsg:  "Service configuration error",
		},
		{
			name:         "Unknown error",
			err:          errors.New("custom error"),
			expectedCode: "INTERNAL_ERROR",
			expectedMsg:  "Internal authentication error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpErr := ErrorToHTTPError(tt.err)
			assert.Equal(t, tt.expectedCode, httpErr.Code)
			assert.Equal(t, tt.expectedMsg, httpErr.Message)

			// For unknown errors, details should be the original error message
			if tt.name == "Unknown error" {
				assert.Equal(t, "custom error", httpErr.Details)
			}
		})
	}
}

func TestHTTPError_Error(t *testing.T) {
	tests := []struct {
		name        string
		httpErr     *HTTPError
		expectedMsg string
	}{
		{
			name: "Error without details",
			httpErr: &HTTPError{
				Code:    "TEST_ERROR",
				Message: "Test error message",
			},
			expectedMsg: "Test error message",
		},
		{
			name: "Error with details",
			httpErr: &HTTPError{
				Code:    "TEST_ERROR",
				Message: "Test error message",
				Details: "Additional details",
			},
			expectedMsg: "Test error message: Additional details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedMsg, tt.httpErr.Error())
		})
	}
}

func TestHTTPError_WithDetails(t *testing.T) {
	httpErr := &HTTPError{
		Code:    "TEST_ERROR",
		Message: "Test error message",
	}

	// Add details
	updatedErr := httpErr.WithDetails("Additional details")

	assert.Equal(t, httpErr, updatedErr) // Should return the same instance
	assert.Equal(t, "Additional details", httpErr.Details)
	assert.Equal(t, "Test error message: Additional details", httpErr.Error())
}

func TestWrappedErrorHandling(t *testing.T) {
	// Test that wrapped errors are handled correctly
	wrappedErr := errors.New("wrapped: " + ErrInvalidToken.Error())

	// This should return default status since it's not directly ErrInvalidToken
	status := ErrorToHTTPStatus(wrappedErr)
	assert.Equal(t, http.StatusInternalServerError, status)

	// But if we use errors.Is logic in a custom error
	customErr := &customError{ErrInvalidToken}
	status = ErrorToHTTPStatus(customErr)
	assert.Equal(t, http.StatusUnauthorized, status)
}

// customError implements error interface and wraps another error
type customError struct {
	underlying error
}

func (e *customError) Error() string {
	return "custom: " + e.underlying.Error()
}

func (e *customError) Is(target error) bool {
	return errors.Is(e.underlying, target)
}

func TestAllDefinedErrors(t *testing.T) {
	// Ensure all defined errors have non-empty messages
	definedErrors := []error{
		ErrInvalidToken,
		ErrTokenExpired,
		ErrInvalidIssuer,
		ErrInvalidAudience,
		ErrInvalidSigningMethod,
		ErrUnauthorized,
		ErrMissingKeyID,
		ErrProviderNotFound,
		ErrCacheKeyNotFound,
		ErrKeyNotFound,
		ErrFailedKeyFetch,
		ErrProviderUnavailable,
		ErrConfigurationError,
		ErrRateLimitExceeded,
		ErrMissingProjectID,
		ErrInvalidKeyFormat,
		ErrNoValidKeys,
		ErrCircuitBreakerOpen,
	}

	for _, err := range definedErrors {
		assert.NotEmpty(t, err.Error(), "Error message should not be empty")

		// Each error should map to a valid HTTP status
		status := ErrorToHTTPStatus(err)
		assert.True(t, status >= 400 && status < 600, "Should map to a valid HTTP error status")

		// Each error should convert to HTTPError
		httpErr := ErrorToHTTPError(err)
		assert.NotEmpty(t, httpErr.Code, "HTTP error code should not be empty")
		assert.NotEmpty(t, httpErr.Message, "HTTP error message should not be empty")
	}
}
