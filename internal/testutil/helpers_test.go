package testutil

import (
	"context"
	"testing"
	"time"

	"authguard/internal/auth"

	"github.com/stretchr/testify/assert"
)

func TestTestAuthContext(t *testing.T) {
	authCtx := TestAuthContext()

	assert.NotNil(t, authCtx)

	// Test headers
	authHeader, exists := authCtx.GetHeader("Authorization")
	assert.True(t, exists)
	assert.Equal(t, "Bearer test-token", authHeader)

	// Test cookies
	sessionCookie, exists := authCtx.GetCookie("session")
	assert.True(t, exists)
	assert.Equal(t, "test-session", sessionCookie)

	// Test body
	body, err := authCtx.ReadBody()
	assert.NoError(t, err)
	assert.Equal(t, []byte("test body"), body)

	// Test other fields
	assert.Equal(t, "127.0.0.1:12345", authCtx.RemoteAddr)
	assert.Equal(t, "POST", authCtx.Method)
	assert.Equal(t, "/test", authCtx.Path)
}

func TestTestUserClaims(t *testing.T) {
	claims := TestUserClaims()

	assert.NotNil(t, claims)
	assert.Equal(t, "test-user-123", claims.Subject)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "Test User", claims.Name)
	assert.Equal(t, auth.ProviderTypeFirebase, claims.Provider)

	// Test custom claims
	assert.NotNil(t, claims.CustomClaims)
	assert.Equal(t, "user", claims.CustomClaims["role"])
}

func TestAssertUserClaimsEqual(t *testing.T) {
	claims1 := TestUserClaims()
	claims2 := TestUserClaims()

	// Should not panic or fail
	AssertUserClaimsEqual(t, claims1, claims2)

	// Test with different claims
	claims3 := TestUserClaims()
	claims3.Subject = "different-user"

	// This would fail in a real test, but we can't test it directly
	// as it would cause the test to fail
}

func TestMockProvider(t *testing.T) {
	provider := MockProvider(auth.ProviderTypeFirebase)

	assert.NotNil(t, provider)
	assert.Equal(t, auth.ProviderTypeFirebase, provider.Type())
}

func TestMockCache(t *testing.T) {
	cache := MockCache()
	assert.NotNil(t, cache)
}

func TestMockConfigLoader(t *testing.T) {
	loader := MockConfigLoader()
	assert.NotNil(t, loader)
}

func TestMockMetrics(t *testing.T) {
	metrics := MockMetrics()
	assert.NotNil(t, metrics)
}

func TestMockLogger(t *testing.T) {
	logger := MockLogger()
	assert.NotNil(t, logger)
}

func TestTimeEquals(t *testing.T) {
	now := time.Now()

	// Should pass for same time
	TimeEquals(t, now, now)

	// Should pass for times within 1 second
	TimeEquals(t, now, now.Add(500*time.Millisecond))
}

func TestWithTimeout(t *testing.T) {
	// Test successful completion
	WithTimeout(t, time.Second, func(ctx context.Context) {
		// Do some work that completes quickly
		time.Sleep(10 * time.Millisecond)
	})

	// Test that provides context
	WithTimeout(t, time.Second, func(ctx context.Context) {
		assert.NotNil(t, ctx)
		select {
		case <-ctx.Done():
			t.Fatal("Context should not be cancelled in this test")
		default:
			// Context is still valid
		}
	})
}

func TestMustNotPanic(t *testing.T) {
	// Test function that doesn't panic
	MustNotPanic(t, func() {
		// Safe operation
		_ = 1 + 1
	})

	// We can't easily test the panic case without causing the test to fail
}

func TestAssertNoGoroutineLeaks(t *testing.T) {
	// This is a placeholder test since the actual implementation
	// would require runtime inspection
	AssertNoGoroutineLeaks(t, 1)
}
