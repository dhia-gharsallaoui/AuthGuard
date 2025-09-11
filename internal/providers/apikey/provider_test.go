package apikey

import (
	"context"
	"testing"
	"time"

	"authguard/internal/auth"
)

// mockCache implements auth.Cache for testing
type mockCache struct {
	data map[string][]byte
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string][]byte),
	}
}

func (m *mockCache) Get(ctx context.Context, key string) ([]byte, error) {
	if data, exists := m.data[key]; exists {
		return data, nil
	}
	return nil, auth.ErrCacheKeyNotFound
}

func (m *mockCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockCache) Clear(ctx context.Context) error {
	m.data = make(map[string][]byte)
	return nil
}

func (m *mockCache) Exists(ctx context.Context, key string) bool {
	_, exists := m.data[key]
	return exists
}

func (m *mockCache) Stats() auth.CacheStats {
	return auth.CacheStats{
		Keys: int64(len(m.data)),
	}
}

func (m *mockCache) Close() error {
	return nil
}

// mockLockManager implements auth.LockManager for testing
type mockLockManager struct{}

func (m *mockLockManager) Lock(key string)   {}
func (m *mockLockManager) Unlock(key string) {}

// mockLogger implements auth.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) Info(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Error(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) With(keysAndValues ...interface{}) auth.Logger  { return m }

// mockMetrics implements auth.Metrics for testing
type mockMetrics struct{}

func (m *mockMetrics) IncValidationAttempts(result string)                                    {}
func (m *mockMetrics) ObserveValidationDuration(provider string, duration time.Duration)      {}
func (m *mockMetrics) IncProviderRequests(provider string)                                    {}
func (m *mockMetrics) IncCacheHits(provider string)                                           {}
func (m *mockMetrics) IncCacheMisses(provider string)                                         {}
func (m *mockMetrics) IncProviderErrors(provider string, errorType string)                    {}
func (m *mockMetrics) ObserveCacheOperationDuration(operation string, duration time.Duration) {}
func (m *mockMetrics) SetActiveConnections(count int)                                         {}
func (m *mockMetrics) SetCachedKeys(provider string, count int)                               {}
func (m *mockMetrics) SetProviderStatus(provider string, healthy bool)                        {}

// mockConfigLoader implements auth.ConfigLoader for testing
type mockConfigLoader struct {
	data map[string]string
}

func newMockConfigLoader(data map[string]string) *mockConfigLoader {
	return &mockConfigLoader{data: data}
}

func (m *mockConfigLoader) Get(key string) (string, bool) {
	value, exists := m.data[key]
	return value, exists
}

func (m *mockConfigLoader) GetBool(key string) (bool, bool) {
	if value, exists := m.data[key]; exists {
		return value == "true", true
	}
	return false, false
}

func (m *mockConfigLoader) GetInt(key string) (int, bool) {
	return 0, false
}

func (m *mockConfigLoader) GetIntWithDefault(key string, defaultValue int) int {
	return defaultValue
}

func (m *mockConfigLoader) GetDuration(key string) (string, bool) {
	return "", false
}

func (m *mockConfigLoader) GetDurationWithDefault(key string, defaultValue string) string {
	return defaultValue
}

func (m *mockConfigLoader) HasPrefix(prefix string) map[string]string {
	return make(map[string]string)
}

func (m *mockConfigLoader) GetWithDefault(key, defaultValue string) string {
	if value, exists := m.data[key]; exists {
		return value
	}
	return defaultValue
}

func (m *mockConfigLoader) GetBoolWithDefault(key string, defaultValue bool) bool {
	if value, exists := m.data[key]; exists {
		return value == "true"
	}
	return defaultValue
}

func TestProvider_Type(t *testing.T) {
	provider := NewProvider(newMockCache(), &mockLockManager{}, &mockLogger{}, &mockMetrics{})

	if provider.Type() != auth.ProviderTypeAPIKey {
		t.Errorf("Expected provider type %v, got %v", auth.ProviderTypeAPIKey, provider.Type())
	}
}

func TestProvider_LoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]string
		expectError bool
	}{
		{
			name: "valid config with keys",
			config: map[string]string{
				"api_key.keys":        "test_key_12345678:user1:test@example.com:Test User",
				"api_key.header_name": "X-API-Key",
			},
			expectError: false,
		},
		{
			name: "valid config with multiple keys",
			config: map[string]string{
				"api_key.keys": "key1_12345678901234:user1:test1@example.com:User One,key2_12345678901234:user2:test2@example.com:User Two",
			},
			expectError: false,
		},
		{
			name: "invalid config - short key",
			config: map[string]string{
				"api_key.keys": "short:user1",
			},
			expectError: true,
		},
		{
			name: "invalid config - no keys",
			config: map[string]string{
				"api_key.header_name": "X-API-Key",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(newMockCache(), &mockLockManager{}, &mockLogger{}, &mockMetrics{})
			loader := newMockConfigLoader(tt.config)

			err := provider.LoadConfig(loader)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestProvider_Validate(t *testing.T) {
	// Setup provider with test configuration
	provider := NewProvider(newMockCache(), &mockLockManager{}, &mockLogger{}, &mockMetrics{})
	config := map[string]string{
		"api_key.keys":        "test_api_key_123456:user123:test@example.com:Test User",
		"api_key.header_name": "X-API-Key",
	}
	loader := newMockConfigLoader(config)

	err := provider.LoadConfig(loader)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name        string
		authCtx     *auth.AuthContext
		expectError bool
		expectedSub string
	}{
		{
			name: "valid API key in header",
			authCtx: &auth.AuthContext{
				Headers: map[string]string{
					"X-API-Key": "test_api_key_123456",
				},
			},
			expectError: false,
			expectedSub: "user123",
		},
		{
			name: "valid API key in Authorization header",
			authCtx: &auth.AuthContext{
				Headers: map[string]string{
					"Authorization": "Bearer test_api_key_123456",
				},
			},
			expectError: false,
			expectedSub: "user123",
		},
		{
			name: "invalid API key",
			authCtx: &auth.AuthContext{
				Headers: map[string]string{
					"X-API-Key": "invalid_key",
				},
			},
			expectError: true,
		},
		{
			name: "missing API key",
			authCtx: &auth.AuthContext{
				Headers: map[string]string{},
			},
			expectError: true,
		},
		{
			name: "empty API key",
			authCtx: &auth.AuthContext{
				Headers: map[string]string{
					"X-API-Key": "",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			claims, err := provider.Validate(ctx, tt.authCtx)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && claims != nil {
				if claims.Subject != tt.expectedSub {
					t.Errorf("Expected subject %s, got %s", tt.expectedSub, claims.Subject)
				}
				if claims.Provider != auth.ProviderTypeAPIKey {
					t.Errorf("Expected provider %v, got %v", auth.ProviderTypeAPIKey, claims.Provider)
				}
				if claims.Email != "test@example.com" {
					t.Errorf("Expected email test@example.com, got %s", claims.Email)
				}
				if claims.Name != "Test User" {
					t.Errorf("Expected name 'Test User', got %s", claims.Name)
				}
			}
		})
	}
}

func TestProvider_ValidateWithCache(t *testing.T) {
	cache := newMockCache()
	provider := NewProvider(cache, &mockLockManager{}, &mockLogger{}, &mockMetrics{})

	config := map[string]string{
		"api_key.keys": "cached_key_123456789:cached_user:cached@example.com:Cached User",
	}
	loader := newMockConfigLoader(config)

	err := provider.LoadConfig(loader)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	authCtx := &auth.AuthContext{
		Headers: map[string]string{
			"X-API-Key": "cached_key_123456789",
		},
	}

	ctx := context.Background()

	// First call - should miss cache and validate
	claims1, err := provider.Validate(ctx, authCtx)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	// Second call - should hit cache
	claims2, err := provider.Validate(ctx, authCtx)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}

	// Claims should be identical
	if claims1.Subject != claims2.Subject {
		t.Error("Cached claims differ from original")
	}
}

func TestProvider_Health(t *testing.T) {
	tests := []struct {
		name        string
		configured  bool
		expectError bool
	}{
		{
			name:        "healthy configured provider",
			configured:  true,
			expectError: false,
		},
		{
			name:        "unhealthy unconfigured provider",
			configured:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(newMockCache(), &mockLockManager{}, &mockLogger{}, &mockMetrics{})

			if tt.configured {
				config := map[string]string{
					"api_key.keys": "health_test_key_123456:health_user:health@example.com:Health User",
				}
				loader := newMockConfigLoader(config)
				err := provider.LoadConfig(loader)
				if err != nil {
					t.Fatalf("Failed to load config: %v", err)
				}
			}

			ctx := context.Background()
			err := provider.Health(ctx)

			if tt.expectError && err == nil {
				t.Error("Expected health check to fail but it passed")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected health check error: %v", err)
			}
		})
	}
}

func TestParseAPIKeysFromString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedLen int
	}{
		{
			name:        "single key",
			input:       "test_key_1234567890123456:user1:email1@example.com:User One",
			expectError: false,
			expectedLen: 1,
		},
		{
			name:        "multiple keys",
			input:       "key1_1234567890123456:user1:email1@example.com:User One,key2_1234567890123456:user2:email2@example.com:User Two",
			expectError: false,
			expectedLen: 2,
		},
		{
			name:        "key without optional fields",
			input:       "simple_key_1234567890:simple_user",
			expectError: false,
			expectedLen: 1,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: false,
			expectedLen: 0,
		},
		{
			name:        "invalid format",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "empty key",
			input:       ":user1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := ParseAPIKeysFromString(tt.input)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && len(keys) != tt.expectedLen {
				t.Errorf("Expected %d keys, got %d", tt.expectedLen, len(keys))
			}
		})
	}
}
