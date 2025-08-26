package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"authguard/internal/auth"
	"authguard/internal/cache"
	"authguard/internal/config"
	"authguard/internal/handlers"
	"authguard/internal/logging"
	"authguard/internal/metrics"
	"authguard/internal/providers/firebase"
	ipwhitelist "authguard/internal/providers/ip_whitelist"
)

func main() {
	var (
		configFile = flag.String("config", "", "Path to configuration file")
		envPrefix  = flag.String("env-prefix", "AUTHGUARD", "Environment variable prefix")
	)
	flag.Parse()

	// Load main configuration
	configLoader := config.NewLoader(*configFile, *envPrefix)
	mainConfig, err := configLoader.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration loading failed: %v\n", err)
		os.Exit(1)
	}

	// Create ConfigLoader for providers
	providerConfigLoader := config.NewEnvConfigLoader(*envPrefix, nil)

	// Initialize logger
	logger, err := logging.NewLogger(mainConfig.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Info("shutting down")

	logger.Info("starting AuthGuard", "version", "0.1.0")

	// Initialize metrics
	metrics, err := metrics.NewMetrics(mainConfig.Metrics)
	if err != nil {
		logger.Error("failed to create metrics", "error", err)
		os.Exit(1)
	}

	// Initialize cache (Redis with memory fallback)
	cacheInstance, err := cache.NewCache(mainConfig.Cache, logger)
	if err != nil {
		logger.Error("failed to create cache", "error", err)
		os.Exit(1)
	}
	defer cacheInstance.Close()

	// Initialize AuthGuard
	authGuard := auth.NewAuthGuard(mainConfig, providerConfigLoader, cacheInstance, metrics, logger)

	// Register providers based on configuration
	if err := registerProviders(authGuard, mainConfig, cacheInstance, authGuard.LockManager(), logger, metrics); err != nil {
		logger.Error("failed to register providers", "error", err)
		os.Exit(1)
	}

	// Create and start HTTP server
	server := handlers.NewServer(mainConfig, authGuard, cacheInstance, logger, metrics)

	// Handle graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Start()
	}()

	// Wait for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("server error", "error", err)
	case sig := <-interrupt:
		logger.Info("received interrupt signal", "signal", sig)
	}

	// Graceful shutdown
	logger.Info("starting graceful shutdown")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), mainConfig.Server.ShutdownTimeout)
	defer shutdownCancel()

	// Channel to signal when shutdown is complete
	shutdownComplete := make(chan error, 1)

	go func() {
		// Stop HTTP server
		if err := server.Stop(shutdownCtx); err != nil {
			logger.Error("server shutdown error", "error", err)
			shutdownComplete <- err
			return
		}

		// Close authguard
		if err := authGuard.Close(); err != nil {
			logger.Error("authguard shutdown error", "error", err)
			shutdownComplete <- err
			return
		}

		shutdownComplete <- nil
	}()

	// Wait for shutdown to complete or timeout
	select {
	case err := <-shutdownComplete:
		if err != nil {
			logger.Error("shutdown failed", "error", err)
		} else {
			logger.Info("shutdown complete")
		}
	case <-shutdownCtx.Done():
		logger.Error("shutdown timeout exceeded, forcing exit")
	}
}

// registerProviders registers authentication providers based on configuration
func registerProviders(authGuard *auth.AuthGuard, config *auth.Config, cache auth.Cache, lockManager auth.LockManager, logger auth.Logger, metrics auth.Metrics) error {
	for _, providerType := range config.Providers {
		switch providerType {
		case auth.ProviderTypeFirebase:
			provider := firebase.NewProvider(cache, lockManager, logger, metrics)
			if err := authGuard.RegisterProvider(provider); err != nil {
				return fmt.Errorf("failed to register firebase provider: %w", err)
			}
		case auth.ProviderTypeIPWhitelist:
			provider := ipwhitelist.NewProvider(cache, lockManager, logger, metrics)
			if err := authGuard.RegisterProvider(provider); err != nil {
				return fmt.Errorf("failed to register ip_whitelist provider: %w", err)
			}
		default:
			logger.Warn("unknown provider type", "provider", providerType)
		}
	}

	return nil
}
