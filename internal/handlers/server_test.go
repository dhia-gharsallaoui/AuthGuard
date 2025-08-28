package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"authguard/internal/auth"
	"authguard/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewServer(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	assert.NotNil(t, server)
	assert.Equal(t, config, server.config)
	assert.Equal(t, mockAuthGuard, server.authGuard)
	assert.Equal(t, mockCache, server.cache)
	assert.Equal(t, mockLoggerWith, server.logger)
	assert.Equal(t, mockMetrics, server.metrics)
	assert.Nil(t, server.httpServer)

	mockLogger.AssertExpectations(t)
}

func TestServer_withMiddleware(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	// Create a simple test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test"))
	})

	// Test middleware chain
	wrappedHandler := server.withMiddleware(testHandler)
	assert.NotNil(t, wrappedHandler)

	// The actual middleware functionality is tested in individual middleware tests
	mockLogger.AssertExpectations(t)
}

func TestServer_withLogging(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	// Mock the Info method
	mockLoggerWith.On("Info", "HTTP request",
		"method", "GET",
		"path", "/test",
		"status", http.StatusOK,
		"duration", mock.AnythingOfType("time.Duration"),
		"user_agent", "",
		"remote_addr", "192.0.2.1:1234")

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	// Create a test handler that returns 200
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with logging middleware
	handler := server.withLogging(testHandler)

	// Test the middleware
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	mockLogger.AssertExpectations(t)
	mockLoggerWith.AssertExpectations(t)
}

func TestServer_withMetrics(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	// Mock metrics methods
	mockMetrics.On("IncValidationAttempts", "success")
	mockMetrics.On("ObserveValidationDuration", "http", mock.AnythingOfType("time.Duration"))

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	// Create a test handler that returns 200
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with metrics middleware
	handler := server.withMetrics(testHandler)

	// Test the middleware with /validate path
	req := httptest.NewRequest(http.MethodPost, "/validate", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	mockLogger.AssertExpectations(t)
	mockMetrics.AssertExpectations(t)
}

func TestServer_withMetrics_NonValidatePath(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	// Only expect duration observation, not validation attempts
	mockMetrics.On("ObserveValidationDuration", "http", mock.AnythingOfType("time.Duration"))

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := server.withMetrics(testHandler)

	// Test with non-validate path
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	mockLogger.AssertExpectations(t)
	mockMetrics.AssertExpectations(t)
}

func TestServer_withMetrics_ValidationFailure(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	// Mock metrics for failure
	mockMetrics.On("IncValidationAttempts", "failure")
	mockMetrics.On("ObserveValidationDuration", "http", mock.AnythingOfType("time.Duration"))

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	// Create a test handler that returns 400
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	handler := server.withMetrics(testHandler)

	req := httptest.NewRequest(http.MethodPost, "/validate", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	mockLogger.AssertExpectations(t)
	mockMetrics.AssertExpectations(t)
}

func TestServer_withCORS(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := server.withCORS(testHandler)

	t.Run("Regular request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", recorder.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Authorization, Content-Type", recorder.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("OPTIONS preflight request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", recorder.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Authorization, Content-Type", recorder.Header().Get("Access-Control-Allow-Headers"))
	})

	mockLogger.AssertExpectations(t)
}

func TestServer_withSecurityHeaders(t *testing.T) {
	config := testutil.TestConfig()
	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := server.withSecurityHeaders(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", recorder.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", recorder.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "max-age=31536000; includeSubDomains", recorder.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "no-store, no-cache, must-revalidate", recorder.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", recorder.Header().Get("Pragma"))

	mockLogger.AssertExpectations(t)
}

func TestResponseWrapper_WriteHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapper := &responseWrapper{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	wrapper.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, wrapper.statusCode)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestServer_Stop(t *testing.T) {
	t.Run("Stop with nil httpServer", func(t *testing.T) {
		config := testutil.TestConfig()
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)
		mockLoggerWith.On("Info", "stopping HTTP server")

		server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

		ctx := context.Background()
		err := server.Stop(ctx)

		assert.NoError(t, err)

		mockLogger.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})

	t.Run("Stop with httpServer graceful shutdown", func(t *testing.T) {
		config := testutil.TestConfig()
		mockAuthGuard := testutil.MockAuthGuard()
		mockCache := testutil.MockCache()
		mockLogger := testutil.MockLogger()
		mockLoggerWith := testutil.MockLogger()
		mockMetrics := testutil.MockMetrics()

		mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)
		mockLoggerWith.On("Info", "stopping HTTP server")
		mockLoggerWith.On("Info", "HTTP server stopped successfully")

		server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

		// Simulate having an httpServer by creating one manually
		server.httpServer = &http.Server{
			Addr:    "localhost:0",
			Handler: http.NewServeMux(),
		}

		ctx := context.Background()
		err := server.Stop(ctx)

		assert.NoError(t, err)

		mockLogger.AssertExpectations(t)
		mockLoggerWith.AssertExpectations(t)
	})
}

func TestServer_Start_ConfigError(t *testing.T) {
	// Create a config that will cause the server to fail to start
	config := &auth.Config{
		Server: auth.ServerConfig{
			Host: "invalid-host-that-does-not-exist-12345",
			Port: "99999", // Invalid port
		},
	}

	mockAuthGuard := testutil.MockAuthGuard()
	mockCache := testutil.MockCache()
	mockLogger := testutil.MockLogger()
	mockLoggerWith := testutil.MockLogger()
	mockLoggerHandlers := testutil.MockLogger()
	mockMetrics := testutil.MockMetrics()

	// Mock server logger
	mockLogger.On("With", []any{"component", "server"}).Return(mockLoggerWith)
	// Mock handlers logger (created in NewHandlers during Start)
	mockLoggerWith.On("With", []any{"component", "handlers"}).Return(mockLoggerHandlers)
	mockLoggerWith.On("Info", "starting HTTP server", "address", "invalid-host-that-does-not-exist-12345:99999")

	server := NewServer(config, mockAuthGuard, mockCache, mockLogger, mockMetrics)

	// This should fail quickly since we can't bind to the invalid address
	err := server.Start()

	// Should get an error trying to bind to invalid address/port
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP server failed")

	mockLogger.AssertExpectations(t)
	mockLoggerWith.AssertExpectations(t)
}
