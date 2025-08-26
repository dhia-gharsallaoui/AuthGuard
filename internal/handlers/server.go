package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"authguard/internal/auth"
)

// Server represents the HTTP server
type Server struct {
	httpServer *http.Server
	config     *auth.Config
	authGuard  *auth.AuthGuard
	cache      auth.Cache
	logger     auth.Logger
	metrics    auth.Metrics
}

// NewServer creates a new HTTP server
func NewServer(config *auth.Config, authGuard *auth.AuthGuard, cache auth.Cache, logger auth.Logger, metrics auth.Metrics) *Server {
	return &Server{
		config:    config,
		authGuard: authGuard,
		cache:     cache,
		logger:    logger.With("component", "server"),
		metrics:   metrics,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Create handlers with dependency injection
	handlers := NewHandlers(s.authGuard, s.cache, s.logger, s.metrics)

	// Register routes
	mux.Handle("/validate", s.withMiddleware(http.HandlerFunc(handlers.ValidateHandler)))
	mux.Handle("/health", s.withMiddleware(http.HandlerFunc(handlers.HealthCheckHandler)))

	// Create HTTP server
	addr := fmt.Sprintf("%s:%s", s.config.Server.Host, s.config.Server.Port)
	s.httpServer = &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    s.config.Server.ReadTimeout,
		WriteTimeout:   s.config.Server.WriteTimeout,
		IdleTimeout:    s.config.Server.IdleTimeout,
		MaxHeaderBytes: s.config.Server.MaxHeaderBytes,
	}

	s.logger.Info("starting HTTP server", "address", addr)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed: %w", err)
	}

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping HTTP server")

	if s.httpServer != nil {
		// First, stop accepting new connections
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("graceful shutdown failed, forcing close", "error", err)
			// Force close if graceful shutdown fails
			if closeErr := s.httpServer.Close(); closeErr != nil {
				s.logger.Error("force close failed", "error", closeErr)
				return closeErr
			}
			return err
		}
		s.logger.Info("HTTP server stopped successfully")
	}

	return nil
}

// withMiddleware applies middleware to handlers
func (s *Server) withMiddleware(handler http.Handler) http.Handler {
	// Apply middleware in reverse order (last applied = first executed)
	handler = s.withLogging(handler)
	handler = s.withMetrics(handler)
	handler = s.withCORS(handler)
	handler = s.withSecurityHeaders(handler)

	return handler
}

// withLogging adds request logging middleware
func (s *Server) withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		handler.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapper.statusCode,
			"duration", duration,
			"user_agent", r.UserAgent(),
			"remote_addr", r.RemoteAddr)
	})
}

// withMetrics adds metrics collection middleware
func (s *Server) withMetrics(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		handler.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		// Increment request counter
		if r.URL.Path == "/validate" {
			if wrapper.statusCode >= 200 && wrapper.statusCode < 300 {
				s.metrics.IncValidationAttempts("success")
			} else {
				s.metrics.IncValidationAttempts("failure")
			}
		}

		// Record response time
		s.metrics.ObserveValidationDuration("http", duration)
	})
}

// withCORS adds CORS headers
func (s *Server) withCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds security headers
func (s *Server) withSecurityHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")

		handler.ServeHTTP(w, r)
	})
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
