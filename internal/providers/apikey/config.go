package apikey

import (
	"fmt"
	"strings"
)

// Config holds the API key provider configuration
type Config struct {
	// APIKeys is a map of API key to user info
	// Format: "key1=user1,key2=user2" or JSON string
	APIKeys map[string]APIKeyInfo `json:"api_keys"`

	// HeaderName is the header name to look for the API key (default: "X-API-Key")
	HeaderName string `json:"header_name"`
}

// APIKeyInfo contains information about an API key user
type APIKeyInfo struct {
	UserID       string         `json:"user_id"`
	Email        string         `json:"email,omitempty"`
	Name         string         `json:"name,omitempty"`
	IsAdmin      bool           `json:"is_admin,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
}

// Validate validates the API key configuration
func (c *Config) Validate() error {
	if len(c.APIKeys) == 0 {
		return fmt.Errorf("at least one API key must be configured")
	}

	// Validate header name
	if c.HeaderName == "" {
		c.HeaderName = "X-API-Key" // Default header name
	}

	// Validate API key entries
	for key, info := range c.APIKeys {
		if key == "" {
			return fmt.Errorf("API key cannot be empty")
		}

		if info.UserID == "" {
			return fmt.Errorf("user_id is required for API key: %s", key)
		}

		// Validate key format (should be at least 16 characters for security)
		if len(key) < 16 {
			return fmt.Errorf("API key must be at least 16 characters long: %s", key)
		}
	}

	return nil
}

// HasAPIKey checks if the given API key exists
func (c *Config) HasAPIKey(apiKey string) bool {
	_, exists := c.APIKeys[apiKey]
	return exists
}

// GetAPIKeyInfo returns the API key info for the given key
func (c *Config) GetAPIKeyInfo(apiKey string) (APIKeyInfo, bool) {
	info, exists := c.APIKeys[apiKey]
	return info, exists
}

// ParseAPIKeysFromString parses API keys from a string format
// Format: "key1:user1:email1:name1,key2:user2:email2:name2"
func ParseAPIKeysFromString(keysStr string) (map[string]APIKeyInfo, error) {
	if keysStr == "" {
		return make(map[string]APIKeyInfo), nil
	}

	keys := make(map[string]APIKeyInfo)
	entries := strings.SplitSeq(keysStr, ",")

	for entry := range entries {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid API key entry format: %s (expected key:user_id[:email[:name]])", entry)
		}

		apiKey := strings.TrimSpace(parts[0])
		userID := strings.TrimSpace(parts[1])

		if apiKey == "" || userID == "" {
			return nil, fmt.Errorf("API key and user_id cannot be empty in entry: %s", entry)
		}

		info := APIKeyInfo{
			UserID: userID,
		}

		// Optional email
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			info.Email = strings.TrimSpace(parts[2])
		}

		// Optional name
		if len(parts) > 3 && strings.TrimSpace(parts[3]) != "" {
			info.Name = strings.TrimSpace(parts[3])
		}

		keys[apiKey] = info
	}

	return keys, nil
}
