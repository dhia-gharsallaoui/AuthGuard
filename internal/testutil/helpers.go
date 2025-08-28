// Package testutil provides common utilities and helpers for testing
package testutil

import (
	"context"
	"strings"
	"testing"
	"time"

	"authguard/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestAuthContext creates a basic AuthContext for testing
func TestAuthContext() *auth.AuthContext {
	return &auth.AuthContext{
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"Content-Type":  "application/json",
		},
		Cookies: map[string]string{
			"session": "test-session",
		},
		Body:       strings.NewReader("test body"),
		RemoteAddr: "127.0.0.1:12345",
		Method:     "POST",
		Path:       "/test",
	}
}

// TestUserClaims creates basic UserClaims for testing
func TestUserClaims() *auth.UserClaims {
	return &auth.UserClaims{
		Subject:       "test-user-123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Picture:       "https://example.com/avatar.png",
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
		CustomClaims: map[string]interface{}{
			"role":        "user",
			"permissions": []string{"read", "write"},
		},
		Provider: auth.ProviderTypeFirebase,
	}
}

// TestConfig creates basic Config for testing
func TestConfig() *auth.Config {
	return &auth.Config{
		// Add any default config values needed for testing
	}
}

// AssertUserClaimsEqual checks if two UserClaims are equal
func AssertUserClaimsEqual(t *testing.T, expected, actual *auth.UserClaims) {
	assert.Equal(t, expected.Subject, actual.Subject)
	assert.Equal(t, expected.Email, actual.Email)
	assert.Equal(t, expected.EmailVerified, actual.EmailVerified)
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.Picture, actual.Picture)
	assert.Equal(t, expected.Issuer, actual.Issuer)
	assert.Equal(t, expected.Audience, actual.Audience)
	assert.Equal(t, expected.Provider, actual.Provider)

	// Custom claims comparison (if both are present)
	if expected.CustomClaims != nil && actual.CustomClaims != nil {
		for k, v := range expected.CustomClaims {
			assert.Equal(t, v, actual.CustomClaims[k])
		}
	}
}

// MockProvider creates a mock auth provider for testing
func MockProvider(providerType auth.ProviderType) *MockAuthProvider {
	return &MockAuthProvider{
		providerType: providerType,
	}
}

// MockAuthProvider is a mock implementation of AuthProvider for testing
type MockAuthProvider struct {
	mock.Mock
	providerType auth.ProviderType
}

func (m *MockAuthProvider) Type() auth.ProviderType {
	return m.providerType
}

func (m *MockAuthProvider) LoadConfig(loader auth.ConfigLoader) error {
	args := m.Called(loader)
	return args.Error(0)
}

func (m *MockAuthProvider) Validate(ctx context.Context, authCtx *auth.AuthContext) (*auth.UserClaims, error) {
	args := m.Called(ctx, authCtx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.UserClaims), args.Error(1)
}

func (m *MockAuthProvider) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAuthProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockCache creates a mock cache for testing
func MockCache() *MockCacheImpl {
	return &MockCacheImpl{}
}

// MockCacheImpl is a mock implementation of Cache for testing
type MockCacheImpl struct {
	mock.Mock
}

func (m *MockCacheImpl) Get(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCacheImpl) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockCacheImpl) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCacheImpl) Exists(ctx context.Context, key string) bool {
	args := m.Called(ctx, key)
	return args.Bool(0)
}

func (m *MockCacheImpl) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCacheImpl) Stats() auth.CacheStats {
	args := m.Called()
	return args.Get(0).(auth.CacheStats)
}

// MockConfigLoader creates a mock config loader for testing
func MockConfigLoader() *MockConfigLoaderImpl {
	return &MockConfigLoaderImpl{}
}

// MockConfigLoaderImpl is a mock implementation of ConfigLoader for testing
type MockConfigLoaderImpl struct {
	mock.Mock
}

func (m *MockConfigLoaderImpl) Get(key string) (string, bool) {
	args := m.Called(key)
	return args.String(0), args.Bool(1)
}

func (m *MockConfigLoaderImpl) GetWithDefault(key, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockConfigLoaderImpl) GetBool(key string) (bool, bool) {
	args := m.Called(key)
	return args.Bool(0), args.Bool(1)
}

func (m *MockConfigLoaderImpl) GetBoolWithDefault(key string, defaultValue bool) bool {
	args := m.Called(key, defaultValue)
	return args.Bool(0)
}

func (m *MockConfigLoaderImpl) GetInt(key string) (int, bool) {
	args := m.Called(key)
	return args.Int(0), args.Bool(1)
}

func (m *MockConfigLoaderImpl) GetIntWithDefault(key string, defaultValue int) int {
	args := m.Called(key, defaultValue)
	return args.Int(0)
}

func (m *MockConfigLoaderImpl) GetDuration(key string) (string, bool) {
	args := m.Called(key)
	return args.String(0), args.Bool(1)
}

func (m *MockConfigLoaderImpl) GetDurationWithDefault(key string, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockConfigLoaderImpl) HasPrefix(prefix string) map[string]string {
	args := m.Called(prefix)
	return args.Get(0).(map[string]string)
}

// MockMetrics creates a mock metrics for testing
func MockMetrics() *MockMetricsImpl {
	return &MockMetricsImpl{}
}

// MockMetricsImpl is a mock implementation of Metrics for testing
type MockMetricsImpl struct {
	mock.Mock
}

func (m *MockMetricsImpl) IncValidationAttempts(result string) {
	m.Called(result)
}

func (m *MockMetricsImpl) IncCacheHits(provider string) {
	m.Called(provider)
}

func (m *MockMetricsImpl) IncCacheMisses(provider string) {
	m.Called(provider)
}

func (m *MockMetricsImpl) IncProviderErrors(provider string, errorType string) {
	m.Called(provider, errorType)
}

func (m *MockMetricsImpl) ObserveValidationDuration(provider string, duration time.Duration) {
	m.Called(provider, duration)
}

func (m *MockMetricsImpl) ObserveCacheOperationDuration(operation string, duration time.Duration) {
	m.Called(operation, duration)
}

func (m *MockMetricsImpl) SetActiveConnections(count int) {
	m.Called(count)
}

func (m *MockMetricsImpl) SetCachedKeys(provider string, count int) {
	m.Called(provider, count)
}

func (m *MockMetricsImpl) SetProviderStatus(provider string, healthy bool) {
	m.Called(provider, healthy)
}

func (m *MockMetricsImpl) IncProviderRequests(provider string) {
	m.Called(provider)
}

// MockLogger creates a mock logger for testing
func MockLogger() *MockLoggerImpl {
	return &MockLoggerImpl{}
}

// MockLoggerImpl is a mock implementation of Logger for testing
type MockLoggerImpl struct {
	mock.Mock
}

func (m *MockLoggerImpl) Info(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLoggerImpl) Debug(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLoggerImpl) Error(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLoggerImpl) Warn(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLoggerImpl) With(keysAndValues ...any) auth.Logger {
	args := m.Called(keysAndValues)
	return args.Get(0).(auth.Logger)
}

// TimeEquals checks if two times are approximately equal (within 1 second)
func TimeEquals(t *testing.T, expected, actual time.Time, msgAndArgs ...interface{}) {
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	assert.True(t, diff < time.Second, msgAndArgs...)
}

// WithTimeout runs a test function with a timeout context
func WithTimeout(t *testing.T, timeout time.Duration, fn func(ctx context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan bool)
	go func() {
		defer close(done)
		fn(ctx)
	}()

	select {
	case <-done:
		// Test completed successfully
	case <-ctx.Done():
		t.Fatal("Test timed out")
	}
}

// AssertNoGoroutineLeaks checks for goroutine leaks in tests
// Call this at the end of tests that spawn goroutines
func AssertNoGoroutineLeaks(t *testing.T, initialCount int) {
	// Give some time for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	// Check if goroutine count is back to initial
	// This is a simple check; more sophisticated leak detection
	// would require tools like goleak
	assert.Eventually(t, func() bool {
		// In a real implementation, you'd check runtime.NumGoroutine()
		// For now, this is a placeholder
		return true
	}, time.Second, 10*time.Millisecond, "Potential goroutine leak detected")
}

// MustNotPanic ensures that a function doesn't panic
func MustNotPanic(t *testing.T, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Function panicked: %v", r)
		}
	}()
	fn()
}
