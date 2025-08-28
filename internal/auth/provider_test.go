package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// Mock implementations for testing

type MockProvider struct {
	mock.Mock
}

func (m *MockProvider) Type() ProviderType {
	args := m.Called()
	return args.Get(0).(ProviderType)
}

func (m *MockProvider) LoadConfig(loader ConfigLoader) error {
	args := m.Called(loader)
	return args.Error(0)
}

func (m *MockProvider) Validate(ctx context.Context, authCtx *AuthContext) (*UserClaims, error) {
	args := m.Called(ctx, authCtx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserClaims), args.Error(1)
}

func (m *MockProvider) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Get(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockCache) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCache) Exists(ctx context.Context, key string) bool {
	args := m.Called(ctx, key)
	return args.Bool(0)
}

func (m *MockCache) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCache) Stats() CacheStats {
	args := m.Called()
	return args.Get(0).(CacheStats)
}

type MockConfigLoader struct {
	mock.Mock
}

func (m *MockConfigLoader) Get(key string) (string, bool) {
	args := m.Called(key)
	return args.String(0), args.Bool(1)
}

func (m *MockConfigLoader) GetWithDefault(key, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockConfigLoader) GetBool(key string) (bool, bool) {
	args := m.Called(key)
	return args.Bool(0), args.Bool(1)
}

func (m *MockConfigLoader) GetBoolWithDefault(key string, defaultValue bool) bool {
	args := m.Called(key, defaultValue)
	return args.Bool(0)
}

func (m *MockConfigLoader) GetInt(key string) (int, bool) {
	args := m.Called(key)
	return args.Int(0), args.Bool(1)
}

func (m *MockConfigLoader) GetIntWithDefault(key string, defaultValue int) int {
	args := m.Called(key, defaultValue)
	return args.Int(0)
}

func (m *MockConfigLoader) GetDuration(key string) (string, bool) {
	args := m.Called(key)
	return args.String(0), args.Bool(1)
}

func (m *MockConfigLoader) GetDurationWithDefault(key string, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockConfigLoader) HasPrefix(prefix string) map[string]string {
	args := m.Called(prefix)
	return args.Get(0).(map[string]string)
}

type MockMetrics struct {
	mock.Mock
}

func (m *MockMetrics) IncValidationAttempts(result string) {
	m.Called(result)
}

func (m *MockMetrics) IncCacheHits(provider string) {
	m.Called(provider)
}

func (m *MockMetrics) IncCacheMisses(provider string) {
	m.Called(provider)
}

func (m *MockMetrics) IncProviderErrors(provider string, errorType string) {
	m.Called(provider, errorType)
}

func (m *MockMetrics) ObserveValidationDuration(provider string, duration time.Duration) {
	m.Called(provider, duration)
}

func (m *MockMetrics) ObserveCacheOperationDuration(operation string, duration time.Duration) {
	m.Called(operation, duration)
}

func (m *MockMetrics) SetActiveConnections(count int) {
	m.Called(count)
}

func (m *MockMetrics) SetCachedKeys(provider string, count int) {
	m.Called(provider, count)
}

func (m *MockMetrics) SetProviderStatus(provider string, healthy bool) {
	m.Called(provider, healthy)
}

func (m *MockMetrics) IncProviderRequests(provider string) {
	m.Called(provider)
}

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Debug(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Error(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Warn(msg string, keysAndValues ...any) {
	args := []any{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) With(keysAndValues ...any) Logger {
	args := m.Called(keysAndValues)
	return args.Get(0).(Logger)
}

// Test ProviderType

func TestProviderType_String(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderType
		expected string
	}{
		{
			name:     "Firebase provider",
			provider: ProviderTypeFirebase,
			expected: "firebase",
		},
		{
			name:     "IP whitelist provider",
			provider: ProviderTypeIPWhitelist,
			expected: "ip_whitelist",
		},
		{
			name:     "Unknown provider",
			provider: ProviderTypeUnknown,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.provider.String())
		})
	}
}

func TestParseProviderType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ProviderType
	}{
		{
			name:     "Parse firebase",
			input:    "firebase",
			expected: ProviderTypeFirebase,
		},
		{
			name:     "Parse ip_whitelist",
			input:    "ip_whitelist",
			expected: ProviderTypeIPWhitelist,
		},
		{
			name:     "Parse unknown",
			input:    "invalid",
			expected: ProviderTypeUnknown,
		},
		{
			name:     "Parse empty string",
			input:    "",
			expected: ProviderTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseProviderType(tt.input))
		})
	}
}

// Test AuthContext

func TestAuthContext_GetHeader(t *testing.T) {
	authCtx := &AuthContext{
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"Content-Type":  "application/json",
			"X-Custom":      "custom-value",
		},
	}

	tests := []struct {
		name          string
		header        string
		expectedValue string
		expectedFound bool
	}{
		{
			name:          "Exact match",
			header:        "Authorization",
			expectedValue: "Bearer token123",
			expectedFound: true,
		},
		{
			name:          "Case insensitive match",
			header:        "authorization",
			expectedValue: "Bearer token123",
			expectedFound: true,
		},
		{
			name:          "Mixed case",
			header:        "content-type",
			expectedValue: "application/json",
			expectedFound: true,
		},
		{
			name:          "Header not found",
			header:        "X-Missing",
			expectedValue: "",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := authCtx.GetHeader(tt.header)
			assert.Equal(t, tt.expectedFound, found)
			assert.Equal(t, tt.expectedValue, value)
		})
	}
}

func TestAuthContext_GetCookie(t *testing.T) {
	authCtx := &AuthContext{
		Cookies: map[string]string{
			"session": "abc123",
			"theme":   "dark",
		},
	}

	tests := []struct {
		name          string
		cookie        string
		expectedValue string
		expectedFound bool
	}{
		{
			name:          "Cookie exists",
			cookie:        "session",
			expectedValue: "abc123",
			expectedFound: true,
		},
		{
			name:          "Cookie not found",
			cookie:        "nonexistent",
			expectedValue: "",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := authCtx.GetCookie(tt.cookie)
			assert.Equal(t, tt.expectedFound, found)
			assert.Equal(t, tt.expectedValue, value)
		})
	}
}

func TestAuthContext_ReadBody(t *testing.T) {
	t.Run("Nil body", func(t *testing.T) {
		authCtx := &AuthContext{Body: nil}
		body, err := authCtx.ReadBody()
		assert.NoError(t, err)
		assert.Nil(t, body)
	})

	t.Run("Valid body", func(t *testing.T) {
		bodyContent := "test body content"
		authCtx := &AuthContext{Body: strings.NewReader(bodyContent)}
		body, err := authCtx.ReadBody()
		assert.NoError(t, err)
		assert.Equal(t, []byte(bodyContent), body)
	})
}

// AuthGuard Test Suite

type AuthGuardTestSuite struct {
	suite.Suite
	authGuard    *AuthGuard
	mockCache    *MockCache
	mockConfig   *Config
	mockLoader   *MockConfigLoader
	mockMetrics  *MockMetrics
	mockLogger   *MockLogger
	mockProvider *MockProvider
}

func (suite *AuthGuardTestSuite) SetupTest() {
	suite.mockCache = &MockCache{}
	suite.mockConfig = &Config{}
	suite.mockLoader = &MockConfigLoader{}
	suite.mockMetrics = &MockMetrics{}
	suite.mockLogger = &MockLogger{}
	suite.mockProvider = &MockProvider{}

	suite.authGuard = NewAuthGuard(
		suite.mockConfig,
		suite.mockLoader,
		suite.mockCache,
		suite.mockMetrics,
		suite.mockLogger,
	)
}

func (suite *AuthGuardTestSuite) TearDownTest() {
	suite.mockCache.AssertExpectations(suite.T())
	suite.mockLoader.AssertExpectations(suite.T())
	suite.mockMetrics.AssertExpectations(suite.T())
	suite.mockLogger.AssertExpectations(suite.T())
	suite.mockProvider.AssertExpectations(suite.T())
}

func (suite *AuthGuardTestSuite) TestNewAuthGuard() {
	assert.NotNil(suite.T(), suite.authGuard)
	assert.NotNil(suite.T(), suite.authGuard.providers)
	assert.Equal(suite.T(), suite.mockCache, suite.authGuard.cache)
	assert.Equal(suite.T(), suite.mockConfig, suite.authGuard.config)
	assert.Equal(suite.T(), suite.mockLoader, suite.authGuard.configLoader)
	assert.Equal(suite.T(), suite.mockMetrics, suite.authGuard.metrics)
	assert.Equal(suite.T(), suite.mockLogger, suite.authGuard.logger)
}

func (suite *AuthGuardTestSuite) TestRegisterProvider_Success() {
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")

	err := suite.authGuard.RegisterProvider(suite.mockProvider)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.mockProvider, suite.authGuard.providers[ProviderTypeFirebase])
}

func (suite *AuthGuardTestSuite) TestRegisterProvider_ConfigError() {
	configErr := errors.New("config load error")
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(configErr)

	err := suite.authGuard.RegisterProvider(suite.mockProvider)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to load config for provider firebase")
	assert.Contains(suite.T(), err.Error(), "config load error")
}

func (suite *AuthGuardTestSuite) TestValidateAuth_Success() {
	ctx := context.Background()
	authCtx := &AuthContext{
		Headers: map[string]string{"Authorization": "Bearer token123"},
	}
	expectedClaims := &UserClaims{
		Subject: "user123",
		Email:   "user@example.com",
	}

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup expectations for validation
	suite.mockProvider.On("Validate", ctx, authCtx).Return(expectedClaims, nil)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "success")
	suite.mockLogger.On("Debug", "authentication validated successfully", "provider", "firebase", "subject", "user123")

	claims, err := suite.authGuard.ValidateAuth(ctx, ProviderTypeFirebase, authCtx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims)
	assert.Equal(suite.T(), "user123", claims.Subject)
	assert.Equal(suite.T(), "user@example.com", claims.Email)
	assert.Equal(suite.T(), ProviderTypeFirebase, claims.Provider)
}

func (suite *AuthGuardTestSuite) TestValidateAuth_ProviderNotFound() {
	ctx := context.Background()
	authCtx := &AuthContext{}

	suite.mockMetrics.On("IncValidationAttempts", "provider_not_found")

	claims, err := suite.authGuard.ValidateAuth(ctx, ProviderTypeFirebase, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), ErrProviderNotFound, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateAuth_ValidationError() {
	ctx := context.Background()
	authCtx := &AuthContext{}
	validationErr := ErrInvalidToken

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup expectations for validation failure
	suite.mockProvider.On("Validate", ctx, authCtx).Return(nil, validationErr)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "failure")
	suite.mockLogger.On("Debug", "authentication validation failed", "provider", "firebase", "error", validationErr)

	claims, err := suite.authGuard.ValidateAuth(ctx, ProviderTypeFirebase, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), validationErr, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateAuth_SystemError() {
	ctx := context.Background()
	authCtx := &AuthContext{}
	systemErr := errors.New("database connection failed")

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup expectations for system error
	suite.mockProvider.On("Validate", ctx, authCtx).Return(nil, systemErr)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "failure")
	suite.mockLogger.On("Error", "authentication validation failed", "provider", "firebase", "error", systemErr)

	claims, err := suite.authGuard.ValidateAuth(ctx, ProviderTypeFirebase, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), systemErr, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_Success() {
	ctx := context.Background()
	authCtx := &AuthContext{
		Headers: map[string]string{"Authorization": "Bearer token123"},
	}

	// Create two providers
	mockProvider1 := &MockProvider{}
	mockProvider2 := &MockProvider{}

	claims1 := &UserClaims{
		Subject: "user123",
		Email:   "user@example.com",
	}
	claims2 := &UserClaims{
		Subject: "user123",
		Name:    "Test User",
	}

	// Register providers
	mockProvider1.On("Type").Return(ProviderTypeFirebase)
	mockProvider1.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(mockProvider1)
	assert.NoError(suite.T(), err)

	mockProvider2.On("Type").Return(ProviderTypeIPWhitelist)
	mockProvider2.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "ip_whitelist")
	err = suite.authGuard.RegisterProvider(mockProvider2)
	assert.NoError(suite.T(), err)

	// Setup validation expectations
	mockProvider1.On("Validate", ctx, authCtx).Return(claims1, nil)
	mockProvider2.On("Validate", ctx, authCtx).Return(claims2, nil)

	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("ObserveValidationDuration", "ip_whitelist", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "success")

	suite.mockLogger.On("Debug", "provider validated successfully in multi-auth", "provider", "firebase", "subject", "user123")
	suite.mockLogger.On("Debug", "provider validated successfully in multi-auth", "provider", "ip_whitelist", "subject", "user123")
	suite.mockLogger.On("Debug", "multi-auth validation successful", "providers", []string{"firebase", "ip_whitelist"}, "subject", "user123")

	providerTypes := []ProviderType{ProviderTypeFirebase, ProviderTypeIPWhitelist}
	claims, err := suite.authGuard.ValidateMultiAuth(ctx, providerTypes, authCtx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims)
	assert.Equal(suite.T(), "user123", claims.Subject)
	assert.Equal(suite.T(), "user@example.com", claims.Email)
	assert.Equal(suite.T(), "Test User", claims.Name)
	assert.Equal(suite.T(), ProviderTypeFirebase, claims.Provider)
	assert.Contains(suite.T(), claims.CustomClaims["auth_providers"], "firebase")
	assert.Contains(suite.T(), claims.CustomClaims["auth_providers"], "ip_whitelist")

	// Clean up mocks
	mockProvider1.AssertExpectations(suite.T())
	mockProvider2.AssertExpectations(suite.T())
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_EmptyProviders() {
	ctx := context.Background()
	authCtx := &AuthContext{}

	claims, err := suite.authGuard.ValidateMultiAuth(ctx, []ProviderType{}, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), ErrProviderNotFound, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_ProviderNotFound() {
	ctx := context.Background()
	authCtx := &AuthContext{}

	suite.mockMetrics.On("IncValidationAttempts", "provider_not_found")
	suite.mockLogger.On("Error", "provider not found in multi-auth", "provider", "firebase")

	providerTypes := []ProviderType{ProviderTypeFirebase}
	claims, err := suite.authGuard.ValidateMultiAuth(ctx, providerTypes, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), ErrProviderNotFound, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_ValidationFailure_UserError() {
	ctx := context.Background()
	authCtx := &AuthContext{}
	userErr := ErrInvalidToken

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup expectations for validation failure
	suite.mockProvider.On("Validate", ctx, authCtx).Return(nil, userErr)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "failure")
	suite.mockLogger.On("Debug", "authentication validation failed in multi-auth",
		"provider", "firebase", "providers", []string{"firebase"}, "error", userErr)

	providerTypes := []ProviderType{ProviderTypeFirebase}
	claims, err := suite.authGuard.ValidateMultiAuth(ctx, providerTypes, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), userErr, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_ValidationFailure_SystemError() {
	ctx := context.Background()
	authCtx := &AuthContext{}
	systemErr := errors.New("database connection failed")

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup expectations for validation failure
	suite.mockProvider.On("Validate", ctx, authCtx).Return(nil, systemErr)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "failure")
	suite.mockLogger.On("Error", "authentication validation failed in multi-auth",
		"provider", "firebase", "providers", []string{"firebase"}, "error", systemErr)

	providerTypes := []ProviderType{ProviderTypeFirebase}
	claims, err := suite.authGuard.ValidateMultiAuth(ctx, providerTypes, authCtx)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), systemErr, err)
	assert.Nil(suite.T(), claims)
}

func (suite *AuthGuardTestSuite) TestValidateMultiAuth_SingleProvider() {
	ctx := context.Background()
	authCtx := &AuthContext{}

	claims := &UserClaims{
		Subject: "user123",
		Email:   "user@example.com",
	}

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup validation expectations
	suite.mockProvider.On("Validate", ctx, authCtx).Return(claims, nil)
	suite.mockMetrics.On("ObserveValidationDuration", "firebase", mock.AnythingOfType("time.Duration"))
	suite.mockMetrics.On("IncValidationAttempts", "success")
	suite.mockLogger.On("Debug", "provider validated successfully in multi-auth", "provider", "firebase", "subject", "user123")
	suite.mockLogger.On("Debug", "multi-auth validation successful", "providers", []string{"firebase"}, "subject", "user123")

	providerTypes := []ProviderType{ProviderTypeFirebase}
	result, err := suite.authGuard.ValidateMultiAuth(ctx, providerTypes, authCtx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.Equal(suite.T(), "user123", result.Subject)
	assert.Equal(suite.T(), "user@example.com", result.Email)
	assert.Equal(suite.T(), ProviderTypeFirebase, result.Provider)
	assert.Nil(suite.T(), result.CustomClaims) // Single provider should not have auth_providers claim
}

func (suite *AuthGuardTestSuite) TestLockManager() {
	lockManager := suite.authGuard.LockManager()
	assert.NotNil(suite.T(), lockManager)
}

func (suite *AuthGuardTestSuite) TestHealth() {
	ctx := context.Background()

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup health check expectation
	suite.mockProvider.On("Health", ctx).Return(nil)

	results := suite.authGuard.Health(ctx)

	assert.NotNil(suite.T(), results)
	assert.NoError(suite.T(), results["firebase"])
}

func (suite *AuthGuardTestSuite) TestClose() {
	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup close expectations
	suite.mockLogger.On("Info", "closing AuthGuard", "providers_count", 1)
	suite.mockLogger.On("Debug", "closing provider", "provider", ProviderTypeFirebase)
	suite.mockProvider.On("Close").Return(nil)
	suite.mockLogger.On("Debug", "provider closed successfully", "provider", ProviderTypeFirebase)
	suite.mockLogger.On("Debug", "closing cache")
	suite.mockCache.On("Close").Return(nil)
	suite.mockLogger.On("Debug", "cache closed successfully")
	suite.mockLogger.On("Info", "AuthGuard closed successfully")

	err = suite.authGuard.Close()

	assert.NoError(suite.T(), err)
}

func (suite *AuthGuardTestSuite) TestClose_ProviderError() {
	providerErr := errors.New("provider close failed")

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup close expectations with provider error
	suite.mockLogger.On("Info", "closing AuthGuard", "providers_count", 1)
	suite.mockLogger.On("Debug", "closing provider", "provider", ProviderTypeFirebase)
	suite.mockProvider.On("Close").Return(providerErr)
	suite.mockLogger.On("Error", "failed to close provider", "provider", ProviderTypeFirebase, "error", providerErr)
	suite.mockLogger.On("Debug", "closing cache")
	suite.mockCache.On("Close").Return(nil)
	suite.mockLogger.On("Debug", "cache closed successfully")
	suite.mockLogger.On("Info", "AuthGuard closed successfully")

	err = suite.authGuard.Close()

	// Should still succeed overall even if provider fails to close
	assert.NoError(suite.T(), err)
}

func (suite *AuthGuardTestSuite) TestClose_CacheError() {
	cacheErr := errors.New("cache close failed")

	// Register the provider first
	suite.mockProvider.On("Type").Return(ProviderTypeFirebase)
	suite.mockProvider.On("LoadConfig", suite.mockLoader).Return(nil)
	suite.mockLogger.On("Info", "registered auth provider", "provider", "firebase")
	err := suite.authGuard.RegisterProvider(suite.mockProvider)
	assert.NoError(suite.T(), err)

	// Setup close expectations with cache error
	suite.mockLogger.On("Info", "closing AuthGuard", "providers_count", 1)
	suite.mockLogger.On("Debug", "closing provider", "provider", ProviderTypeFirebase)
	suite.mockProvider.On("Close").Return(nil)
	suite.mockLogger.On("Debug", "provider closed successfully", "provider", ProviderTypeFirebase)
	suite.mockLogger.On("Debug", "closing cache")
	suite.mockCache.On("Close").Return(cacheErr)
	suite.mockLogger.On("Error", "failed to close cache", "error", cacheErr)

	err = suite.authGuard.Close()

	// Should fail if cache fails to close
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), cacheErr, err)
}

func TestMergeClaims(t *testing.T) {
	config := &Config{}
	mockLoader := &MockConfigLoader{}
	mockCache := &MockCache{}
	mockMetrics := &MockMetrics{}
	mockLogger := &MockLogger{}

	authGuard := NewAuthGuard(config, mockLoader, mockCache, mockMetrics, mockLogger)

	baseTime := time.Now()
	newTime := baseTime.Add(time.Hour)

	t.Run("Merge all fields", func(t *testing.T) {
		baseClaims := &UserClaims{
			Subject:       "olduser",
			Email:         "old@example.com",
			EmailVerified: false,
			Name:          "Old Name",
			Picture:       "old-pic.jpg",
			IssuedAt:      baseTime,
			ExpiresAt:     baseTime.Add(time.Minute * 30),
			Issuer:        "old-issuer",
			Audience:      []string{"old-aud"},
			CustomClaims:  map[string]any{"old": "value"},
		}

		newClaims := &UserClaims{
			Subject:       "newuser",
			Email:         "new@example.com",
			EmailVerified: true,
			Name:          "New Name",
			Picture:       "new-pic.jpg",
			IssuedAt:      newTime,
			ExpiresAt:     newTime.Add(time.Minute * 30),
			Issuer:        "new-issuer",
			Audience:      []string{"new-aud"},
			CustomClaims:  map[string]any{"new": "value"},
		}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		assert.Equal(t, "newuser", result.Subject)
		assert.Equal(t, "new@example.com", result.Email)
		assert.True(t, result.EmailVerified)
		assert.Equal(t, "New Name", result.Name)
		assert.Equal(t, "new-pic.jpg", result.Picture)
		assert.Equal(t, newTime, result.IssuedAt)
		assert.Equal(t, newTime.Add(time.Minute*30), result.ExpiresAt)
		assert.Equal(t, "new-issuer", result.Issuer)
		assert.Equal(t, []string{"new-aud"}, result.Audience)
		assert.Contains(t, result.CustomClaims, "old")
		assert.Contains(t, result.CustomClaims, "new")
	})

	t.Run("Merge with empty new claims", func(t *testing.T) {
		baseClaims := &UserClaims{
			Subject:       "user",
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "User Name",
			Picture:       "pic.jpg",
			IssuedAt:      baseTime,
			ExpiresAt:     baseTime.Add(time.Hour),
			Issuer:        "issuer",
			Audience:      []string{"aud"},
			CustomClaims:  map[string]any{"key": "value"},
		}

		newClaims := &UserClaims{}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		// All original values should remain
		assert.Equal(t, "user", result.Subject)
		assert.Equal(t, "user@example.com", result.Email)
		assert.True(t, result.EmailVerified)
		assert.Equal(t, "User Name", result.Name)
		assert.Equal(t, "pic.jpg", result.Picture)
		assert.Equal(t, baseTime, result.IssuedAt)
		assert.Equal(t, baseTime.Add(time.Hour), result.ExpiresAt)
		assert.Equal(t, "issuer", result.Issuer)
		assert.Equal(t, []string{"aud"}, result.Audience)
		assert.Equal(t, map[string]any{"key": "value"}, result.CustomClaims)
	})

	t.Run("Merge with nil base custom claims", func(t *testing.T) {
		baseClaims := &UserClaims{
			Subject:      "user",
			CustomClaims: nil,
		}

		newClaims := &UserClaims{
			CustomClaims: map[string]any{"new": "value"},
		}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		assert.NotNil(t, result.CustomClaims)
		assert.Equal(t, "value", result.CustomClaims["new"])
	})

	t.Run("Merge with nil new custom claims", func(t *testing.T) {
		baseClaims := &UserClaims{
			Subject:      "user",
			CustomClaims: map[string]any{"existing": "value"},
		}

		newClaims := &UserClaims{
			CustomClaims: nil,
		}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		assert.Equal(t, map[string]any{"existing": "value"}, result.CustomClaims)
	})

	t.Run("Merge with zero time values", func(t *testing.T) {
		baseClaims := &UserClaims{
			IssuedAt:  baseTime,
			ExpiresAt: baseTime.Add(time.Hour),
		}

		newClaims := &UserClaims{
			IssuedAt:  time.Time{}, // Zero time
			ExpiresAt: time.Time{}, // Zero time
		}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		// Original times should remain
		assert.Equal(t, baseTime, result.IssuedAt)
		assert.Equal(t, baseTime.Add(time.Hour), result.ExpiresAt)
	})

	t.Run("Merge with empty audience", func(t *testing.T) {
		baseClaims := &UserClaims{
			Audience: []string{"original-aud"},
		}

		newClaims := &UserClaims{
			Audience: []string{}, // Empty audience
		}

		result := authGuard.mergeClaims(baseClaims, newClaims, ProviderTypeFirebase)

		// Original audience should remain
		assert.Equal(t, []string{"original-aud"}, result.Audience)
	})
}

func TestIsUserError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Invalid token error",
			err:      ErrInvalidToken,
			expected: true,
		},
		{
			name:     "Token expired error",
			err:      ErrTokenExpired,
			expected: true,
		},
		{
			name:     "Invalid issuer error",
			err:      ErrInvalidIssuer,
			expected: true,
		},
		{
			name:     "Invalid audience error",
			err:      ErrInvalidAudience,
			expected: true,
		},
		{
			name:     "Invalid signing method error",
			err:      ErrInvalidSigningMethod,
			expected: true,
		},
		{
			name:     "Missing key ID error",
			err:      ErrMissingKeyID,
			expected: true,
		},
		{
			name:     "Unauthorized error",
			err:      ErrUnauthorized,
			expected: true,
		},
		{
			name:     "System error",
			err:      errors.New("database connection failed"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isUserError(tt.err))
		})
	}
}

func TestAuthGuardTestSuite(t *testing.T) {
	suite.Run(t, new(AuthGuardTestSuite))
}
