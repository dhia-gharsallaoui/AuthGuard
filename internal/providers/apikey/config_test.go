package apikey

import (
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				APIKeys: map[string]APIKeyInfo{
					"test_key_1234567890": {UserID: "user1"},
				},
				HeaderName: "X-API-Key",
			},
			expectError: false,
		},
		{
			name: "empty API keys",
			config: &Config{
				APIKeys:    map[string]APIKeyInfo{},
				HeaderName: "X-API-Key",
			},
			expectError: true,
		},
		{
			name: "short API key",
			config: &Config{
				APIKeys: map[string]APIKeyInfo{
					"short": {UserID: "user1"},
				},
			},
			expectError: true,
		},
		{
			name: "empty user ID",
			config: &Config{
				APIKeys: map[string]APIKeyInfo{
					"test_key_1234567890": {UserID: ""},
				},
			},
			expectError: true,
		},
		{
			name: "default header name",
			config: &Config{
				APIKeys: map[string]APIKeyInfo{
					"test_key_1234567890": {UserID: "user1"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}

			// Check defaults are set
			if !tt.expectError {
				if tt.config.HeaderName == "" {
					t.Error("HeaderName should have been set to default")
				}
			}
		})
	}
}

func TestConfig_HasAPIKey(t *testing.T) {
	config := &Config{
		APIKeys: map[string]APIKeyInfo{
			"existing_key_123456": {UserID: "user1"},
		},
	}

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "existing key",
			key:      "existing_key_123456",
			expected: true,
		},
		{
			name:     "non-existing key",
			key:      "non_existing_key",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.HasAPIKey(tt.key)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConfig_GetAPIKeyInfo(t *testing.T) {
	testInfo := APIKeyInfo{
		UserID: "user1",
		Email:  "test@example.com",
		Name:   "Test User",
	}

	config := &Config{
		APIKeys: map[string]APIKeyInfo{
			"existing_key_123456": testInfo,
		},
	}

	tests := []struct {
		name       string
		key        string
		expectOK   bool
		expectInfo APIKeyInfo
	}{
		{
			name:       "existing key",
			key:        "existing_key_123456",
			expectOK:   true,
			expectInfo: testInfo,
		},
		{
			name:     "non-existing key",
			key:      "non_existing_key",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := config.GetAPIKeyInfo(tt.key)
			if ok != tt.expectOK {
				t.Errorf("Expected ok=%v, got ok=%v", tt.expectOK, ok)
			}
			if tt.expectOK {
				if info.UserID != tt.expectInfo.UserID {
					t.Errorf("Expected UserID %s, got %s", tt.expectInfo.UserID, info.UserID)
				}
				if info.Email != tt.expectInfo.Email {
					t.Errorf("Expected Email %s, got %s", tt.expectInfo.Email, info.Email)
				}
				if info.Name != tt.expectInfo.Name {
					t.Errorf("Expected Name %s, got %s", tt.expectInfo.Name, info.Name)
				}
			}
		})
	}
}
