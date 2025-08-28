package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authguard/internal/auth"
	"authguard/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// FailingResponseWriter is a mock response writer that can simulate write failures
type FailingResponseWriter struct {
	http.ResponseWriter
	shouldFailWrite bool
}

func (f *FailingResponseWriter) Write(data []byte) (int, error) {
	if f.shouldFailWrite {
		return 0, errors.New("simulated write failure")
	}
	return f.ResponseWriter.Write(data)
}

func TestHealthStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected string
	}{
		{
			name:     "Healthy status",
			status:   HealthStatusHealthy,
			expected: "healthy",
		},
		{
			name:     "Unhealthy status",
			status:   HealthStatusUnhealthy,
			expected: "unhealthy",
		},
		{
			name:     "Degraded status",
			status:   HealthStatusDegraded,
			expected: "degraded",
		},
		{
			name:     "Unknown status",
			status:   HealthStatus(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestHealthStatus_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected string
	}{
		{
			name:     "Healthy status JSON",
			status:   HealthStatusHealthy,
			expected: `"healthy"`,
		},
		{
			name:     "Unhealthy status JSON",
			status:   HealthStatusUnhealthy,
			expected: `"unhealthy"`,
		},
		{
			name:     "Degraded status JSON",
			status:   HealthStatusDegraded,
			expected: `"degraded"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.status.MarshalJSON()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestNewHandlers(t *testing.T) {
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	// Mock the With method for logger
	mockLoggerWith := testutil.MockLogger()
	mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

	handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

	assert.NotNil(t, handlers)
	assert.Equal(t, mockAuthGuard, handlers.authGuard)
	assert.Equal(t, mockCache, handlers.cache)
	assert.Equal(t, mockLoggerWith, handlers.logger)
	assert.Equal(t, mockMetrics, handlers.metrics)

	mockLogger.AssertExpectations(t)
}

func TestHandlers_ValidateHandler(t *testing.T) {
	t.Run("Successful validation with single provider", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		userClaims := testutil.TestUserClaims()
		mockAuthGuard.On("ValidateAuth",
			mock.Anything,
			auth.ProviderTypeFirebase,
			mock.AnythingOfType("*auth.AuthContext")).Return(userClaims, nil)

		mockLoggerWith.On("Debug", "authentication validation successful",
			"providers", []auth.ProviderType{auth.ProviderTypeFirebase},
			"subject", "test-user-123",
			"duration", mock.AnythingOfType("time.Duration"))

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBuffer([]byte("test body")))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.ValidateHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "test-user-123", recorder.Header().Get("X-User-ID"))
		assert.Equal(t, "firebase", recorder.Header().Get("X-User-Provider"))
		assert.Equal(t, "test@example.com", recorder.Header().Get("X-User-Email"))
		assert.Equal(t, "Test User", recorder.Header().Get("X-User-Name"))
		assert.Equal(t, "true", recorder.Header().Get("X-User-Email-Verified"))

		mockAuthGuard.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("Successful validation with multiple providers", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		userClaims := testutil.TestUserClaims()
		providerTypes := []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}

		mockAuthGuard.On("ValidateMultiAuth",
			mock.Anything,
			providerTypes,
			mock.AnythingOfType("*auth.AuthContext")).Return(userClaims, nil)

		mockLoggerWith.On("Debug", "authentication validation successful",
			"providers", providerTypes,
			"subject", "test-user-123",
			"duration", mock.AnythingOfType("time.Duration"))

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request with multiple providers
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", "firebase,ip_whitelist")

		// Create response recorder
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.ValidateHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "test-user-123", recorder.Header().Get("X-User-ID"))

		mockAuthGuard.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("Validation failure", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		validationErr := auth.ErrInvalidToken
		mockAuthGuard.On("ValidateAuth",
			mock.Anything,
			auth.ProviderTypeFirebase,
			mock.AnythingOfType("*auth.AuthContext")).Return(nil, validationErr)

		mockLoggerWith.On("Debug", "authentication validation failed",
			"providers", []auth.ProviderType{auth.ProviderTypeFirebase},
			"error", validationErr)

		mockLoggerWith.On("Debug", "authentication error",
			"code", "INVALID_TOKEN",
			"message", "Invalid authentication token",
			"details", "",
			"status", http.StatusUnauthorized)

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)

		// Create response recorder
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.ValidateHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var errorResponse auth.HTTPError
		err := json.NewDecoder(recorder.Body).Decode(&errorResponse)
		assert.NoError(t, err)
		assert.Equal(t, "INVALID_TOKEN", errorResponse.Code)
		assert.Equal(t, "Invalid authentication token", errorResponse.Message)

		mockAuthGuard.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("With unknown provider in header", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		userClaims := testutil.TestUserClaims()
		mockAuthGuard.On("ValidateAuth",
			mock.Anything,
			auth.ProviderTypeFirebase,
			mock.AnythingOfType("*auth.AuthContext")).Return(userClaims, nil)

		mockLoggerWith.On("Warn", "unknown provider type", "provider", "unknown")
		mockLoggerWith.On("Debug", "authentication validation successful",
			"providers", []auth.ProviderType{auth.ProviderTypeFirebase},
			"subject", "test-user-123",
			"duration", mock.AnythingOfType("time.Duration"))

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request with unknown provider (should fall back to firebase)
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", "firebase,unknown")

		// Create response recorder
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.ValidateHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusOK, recorder.Code)

		mockAuthGuard.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})
}

func TestHandlers_HealthCheckHandler(t *testing.T) {
	t.Run("All providers healthy", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		// Mock healthy providers
		providerResults := map[string]error{
			"firebase": nil,
		}
		mockAuthGuard.On("Health", mock.Anything).Return(providerResults)

		// Mock cache stats
		cacheStats := auth.CacheStats{
			Type:        auth.CacheTypeMemory,
			Keys:        100,
			Hits:        50,
			Misses:      10,
			LastUpdated: time.Now(),
		}
		mockCache.On("Stats").Return(cacheStats)

		mockLoggerWith.On("Debug", "health check completed",
			"status", HealthStatusHealthy,
			"providers_count", 1)

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.HealthCheckHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		// Check JSON structure manually since HealthStatus marshals as string
		var jsonResponse map[string]interface{}
		err := json.NewDecoder(recorder.Body).Decode(&jsonResponse)
		assert.NoError(t, err)
		assert.Equal(t, "healthy", jsonResponse["status"])
		assert.Contains(t, jsonResponse, "providers")
		assert.Contains(t, jsonResponse, "cache")

		providers := jsonResponse["providers"].(map[string]interface{})
		firebase := providers["firebase"].(map[string]interface{})
		assert.Equal(t, "healthy", firebase["status"])

		mockAuthGuard.AssertExpectations(t)
		mockCache.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("Provider unhealthy", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		// Mock unhealthy provider
		providerErr := errors.New("connection failed")
		providerResults := map[string]error{
			"firebase": providerErr,
		}
		mockAuthGuard.On("Health", mock.Anything).Return(providerResults)

		// Mock cache stats
		cacheStats := auth.CacheStats{
			Type: auth.CacheTypeRedis,
		}
		mockCache.On("Stats").Return(cacheStats)

		mockLoggerWith.On("Debug", "health check completed",
			"status", HealthStatusUnhealthy,
			"providers_count", 1)

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create request
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		recorder := httptest.NewRecorder()

		// Call handler
		handlers.HealthCheckHandler(recorder, req)

		// Assertions
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		// Check JSON structure manually since HealthStatus marshals as string
		var jsonResponse map[string]interface{}
		err := json.NewDecoder(recorder.Body).Decode(&jsonResponse)
		assert.NoError(t, err)
		assert.Equal(t, "unhealthy", jsonResponse["status"])

		providers := jsonResponse["providers"].(map[string]interface{})
		firebase := providers["firebase"].(map[string]interface{})
		assert.Equal(t, "unhealthy", firebase["status"])
		assert.Equal(t, "connection failed", firebase["error"])

		mockAuthGuard.AssertExpectations(t)
		mockCache.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("JSON encoding error", func(t *testing.T) {
		// Setup mocks
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

		// Mock healthy providers
		providerResults := map[string]error{
			"firebase": nil,
		}
		mockAuthGuard.On("Health", mock.Anything).Return(providerResults)

		// Mock cache stats
		cacheStats := auth.CacheStats{
			Type: auth.CacheTypeMemory,
		}
		mockCache.On("Stats").Return(cacheStats)

		// Mock logger with error when JSON encoding fails
		mockLoggerWith.On("Error", "failed to encode health response", "error", mock.AnythingOfType("*errors.errorString"))
		mockLoggerWith.On("Debug", "health check completed",
			"status", HealthStatusHealthy,
			"providers_count", 1)

		handlers := NewHandlers(mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Create a request
		req := httptest.NewRequest(http.MethodGet, "/health", nil)

		// Create a custom response writer that will cause JSON encoding to fail
		recorder := &FailingResponseWriter{ResponseWriter: httptest.NewRecorder(), shouldFailWrite: true}

		// Call handler - this should trigger the JSON encoding error path
		handlers.HealthCheckHandler(recorder, req)

		mockAuthGuard.AssertExpectations(t)
		mockCache.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})
}

func TestHandlers_setUserHeaders(t *testing.T) {
	handlers := &Handlers{} // No mocks needed for this test

	t.Run("All fields populated", func(t *testing.T) {
		claims := testutil.TestUserClaims()
		recorder := httptest.NewRecorder()

		handlers.setUserHeaders(recorder, claims)

		assert.Equal(t, "test-user-123", recorder.Header().Get("X-User-ID"))
		assert.Equal(t, "firebase", recorder.Header().Get("X-User-Provider"))
		assert.Equal(t, "test@example.com", recorder.Header().Get("X-User-Email"))
		assert.Equal(t, "Test User", recorder.Header().Get("X-User-Name"))
		assert.Equal(t, "true", recorder.Header().Get("X-User-Email-Verified"))
		assert.NotEmpty(t, recorder.Header().Get("X-Token-Expires"))
	})

	t.Run("Minimal fields", func(t *testing.T) {
		claims := &auth.UserClaims{
			Subject:       "user123",
			Provider:      auth.ProviderTypeIPWhitelist,
			EmailVerified: false,
			ExpiresAt:     time.Now().Add(time.Hour),
		}
		recorder := httptest.NewRecorder()

		handlers.setUserHeaders(recorder, claims)

		assert.Equal(t, "user123", recorder.Header().Get("X-User-ID"))
		assert.Equal(t, "ip_whitelist", recorder.Header().Get("X-User-Provider"))
		assert.Empty(t, recorder.Header().Get("X-User-Email"))
		assert.Empty(t, recorder.Header().Get("X-User-Name"))
		assert.Empty(t, recorder.Header().Get("X-User-Email-Verified"))
		assert.NotEmpty(t, recorder.Header().Get("X-Token-Expires"))
	})
}

func TestHandlers_parseProviders(t *testing.T) {
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

	handlers := &Handlers{
		logger: mockLoggerWith,
	}

	t.Run("Single provider", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", "firebase")

		providers := handlers.parseProviders(req)

		assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase}, providers)
	})

	t.Run("Multiple providers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", "firebase,ip_whitelist")

		providers := handlers.parseProviders(req)

		expected := []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}
		assert.Equal(t, expected, providers)
	})

	t.Run("No providers header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)

		providers := handlers.parseProviders(req)

		assert.Empty(t, providers)
	})

	t.Run("Unknown provider", func(t *testing.T) {
		mockLoggerWith.On("Warn", "unknown provider type", "provider", "unknown")

		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", "firebase,unknown")

		providers := handlers.parseProviders(req)

		assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase}, providers)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("With whitespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Set("X-Auth-Providers", " firebase , ip_whitelist ")

		providers := handlers.parseProviders(req)

		expected := []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}
		assert.Equal(t, expected, providers)
	})
}

func TestHandlers_createAuthContext(t *testing.T) {
	handlers := &Handlers{} // No mocks needed

	t.Run("Complete request", func(t *testing.T) {
		body := strings.NewReader("test body")
		req := httptest.NewRequest(http.MethodPost, "/validate", body)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "session", Value: "session123"})
		req.RemoteAddr = "192.168.1.1:12345"

		authCtx := handlers.createAuthContext(req)

		assert.Equal(t, "Bearer token", authCtx.Headers["Authorization"])
		assert.Equal(t, "application/json", authCtx.Headers["Content-Type"])
		assert.Equal(t, "session123", authCtx.Cookies["session"])
		// Can't directly compare bodies since HTTP wraps them
		assert.NotNil(t, authCtx.Body)
		assert.Equal(t, "192.168.1.1:12345", authCtx.RemoteAddr)
		assert.Equal(t, "POST", authCtx.Method)
		assert.Equal(t, "/validate", authCtx.Path)
	})

	t.Run("Empty request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		authCtx := handlers.createAuthContext(req)

		assert.NotNil(t, authCtx.Headers)
		assert.NotNil(t, authCtx.Cookies)
		assert.Equal(t, "GET", authCtx.Method)
		assert.Equal(t, "/test", authCtx.Path)
	})

	t.Run("Multiple header values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/validate", nil)
		req.Header.Add("X-Custom", "value1")
		req.Header.Add("X-Custom", "value2")

		authCtx := handlers.createAuthContext(req)

		// Should only get the first value
		assert.Equal(t, "value1", authCtx.Headers["X-Custom"])
	})
}

func TestHandlers_writeError(t *testing.T) {
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockLogger.On("With", []any{"component", "handlers"}).Return(mockLoggerWith)

	handlers := &Handlers{
		logger: mockLoggerWith,
	}

	t.Run("Write error successfully", func(t *testing.T) {
		httpErr := &auth.HTTPError{
			Code:    "TEST_ERROR",
			Message: "Test error message",
			Details: "Test details",
		}

		mockLoggerWith.On("Debug", "authentication error",
			"code", "TEST_ERROR",
			"message", "Test error message",
			"details", "Test details",
			"status", http.StatusBadRequest)

		recorder := httptest.NewRecorder()
		handlers.writeError(recorder, httpErr, http.StatusBadRequest)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var response auth.HTTPError
		err := json.NewDecoder(recorder.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, httpErr.Code, response.Code)
		assert.Equal(t, httpErr.Message, response.Message)
		assert.Equal(t, httpErr.Details, response.Details)

		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("JSON encoding failure", func(t *testing.T) {
		httpErr := &auth.HTTPError{
			Code:    "TEST_ERROR",
			Message: "Test error message",
		}

		mockLoggerWith.On("Warn", "failed to encode error response", "error", mock.AnythingOfType("*errors.errorString"))
		mockLoggerWith.On("Debug", "authentication error",
			"code", "TEST_ERROR",
			"message", "Test error message",
			"details", "",
			"status", http.StatusBadRequest)

		recorder := &FailingResponseWriter{ResponseWriter: httptest.NewRecorder(), shouldFailWrite: true}
		handlers.writeError(recorder, httpErr, http.StatusBadRequest)

		assert.Equal(t, http.StatusBadRequest, recorder.ResponseWriter.(*httptest.ResponseRecorder).Code)
		assert.Equal(t, "application/json", recorder.ResponseWriter.(*httptest.ResponseRecorder).Header().Get("Content-Type"))

		mockLoggerWith.AssertExpectations(t)
	})
}
