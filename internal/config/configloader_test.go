package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnvConfigLoader(t *testing.T) {
	tests := []struct {
		name      string
		envPrefix string
		yamlData  map[string]any
		expected  *EnvConfigLoader
	}{
		{
			name:      "with yaml data",
			envPrefix: "TEST",
			yamlData:  map[string]any{"key": "value"},
			expected: &EnvConfigLoader{
				envPrefix: "TEST",
				yamlData:  map[string]any{"key": "value"},
			},
		},
		{
			name:      "without yaml data",
			envPrefix: "TEST",
			yamlData:  nil,
			expected: &EnvConfigLoader{
				envPrefix: "TEST",
				yamlData:  map[string]any{},
			},
		},
		{
			name:      "empty prefix",
			envPrefix: "",
			yamlData:  map[string]any{"test": "data"},
			expected: &EnvConfigLoader{
				envPrefix: "",
				yamlData:  map[string]any{"test": "data"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewEnvConfigLoader(tt.envPrefix, tt.yamlData)
			assert.Equal(t, tt.expected, loader)
		})
	}
}

func TestEnvConfigLoader_Get(t *testing.T) {
	// Setup test environment
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"yaml": map[string]any{
			"key": "yaml_value",
		},
		"simple": "simple_value",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name     string
		key      string
		envVar   string
		envValue string
		expected string
		found    bool
	}{
		{
			name:     "environment variable found",
			key:      "env.key",
			envVar:   "TEST_ENV_KEY",
			envValue: "env_value",
			expected: "env_value",
			found:    true,
		},
		{
			name:     "yaml value found when env not set",
			key:      "yaml.key",
			expected: "yaml_value",
			found:    true,
		},
		{
			name:     "simple yaml value",
			key:      "simple",
			expected: "simple_value",
			found:    true,
		},
		{
			name:     "env takes precedence over yaml",
			key:      "yaml.key",
			envVar:   "TEST_YAML_KEY",
			envValue: "env_override",
			expected: "env_override",
			found:    true,
		},
		{
			name:     "key not found",
			key:      "missing.key",
			expected: "",
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variable if specified
			if tt.envVar != "" {
				err := os.Setenv(tt.envVar, tt.envValue)
				require.NoError(t, err)
				defer func() {
					err := os.Unsetenv(tt.envVar)
					require.NoError(t, err)
				}()
			}

			value, found := loader.Get(tt.key)
			assert.Equal(t, tt.expected, value)
			assert.Equal(t, tt.found, found)
		})
	}
}

func TestEnvConfigLoader_GetWithDefault(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"existing": "yaml_value",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name         string
		key          string
		defaultValue string
		expected     string
	}{
		{
			name:         "returns existing value",
			key:          "existing",
			defaultValue: "default",
			expected:     "yaml_value",
		},
		{
			name:         "returns default for missing key",
			key:          "missing",
			defaultValue: "default_value",
			expected:     "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := loader.GetWithDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvConfigLoader_GetBool(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"yaml_true":    "true",
		"yaml_false":   "false",
		"yaml_invalid": "not_bool",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name     string
		key      string
		envVar   string
		envValue string
		expected bool
		found    bool
	}{
		{
			name:     "true from env",
			key:      "bool.key",
			envVar:   "TEST_BOOL_KEY",
			envValue: "true",
			expected: true,
			found:    true,
		},
		{
			name:     "false from env",
			key:      "bool.key",
			envVar:   "TEST_BOOL_KEY",
			envValue: "false",
			expected: false,
			found:    true,
		},
		{
			name:     "1 from env (true)",
			key:      "bool.key",
			envVar:   "TEST_BOOL_KEY",
			envValue: "1",
			expected: true,
			found:    true,
		},
		{
			name:     "0 from env (false)",
			key:      "bool.key",
			envVar:   "TEST_BOOL_KEY",
			envValue: "0",
			expected: false,
			found:    true,
		},
		{
			name:     "true from yaml",
			key:      "yaml_true",
			expected: true,
			found:    true,
		},
		{
			name:     "false from yaml",
			key:      "yaml_false",
			expected: false,
			found:    true,
		},
		{
			name:     "invalid bool value",
			key:      "yaml_invalid",
			expected: false,
			found:    false,
		},
		{
			name:     "missing key",
			key:      "missing",
			expected: false,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				err := os.Setenv(tt.envVar, tt.envValue)
				require.NoError(t, err)
				defer func() {
					err := os.Unsetenv(tt.envVar)
					require.NoError(t, err)
				}()
			}

			value, found := loader.GetBool(tt.key)
			assert.Equal(t, tt.expected, value)
			assert.Equal(t, tt.found, found)
		})
	}
}

func TestEnvConfigLoader_GetBoolWithDefault(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"existing": "true",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name         string
		key          string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "returns existing bool value",
			key:          "existing",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns default for missing key",
			key:          "missing",
			defaultValue: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := loader.GetBoolWithDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvConfigLoader_GetInt(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"yaml_int":     "42",
		"yaml_invalid": "not_int",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name     string
		key      string
		envVar   string
		envValue string
		expected int
		found    bool
	}{
		{
			name:     "int from env",
			key:      "int.key",
			envVar:   "TEST_INT_KEY",
			envValue: "123",
			expected: 123,
			found:    true,
		},
		{
			name:     "negative int from env",
			key:      "int.key",
			envVar:   "TEST_INT_KEY",
			envValue: "-456",
			expected: -456,
			found:    true,
		},
		{
			name:     "int from yaml",
			key:      "yaml_int",
			expected: 42,
			found:    true,
		},
		{
			name:     "invalid int value",
			key:      "yaml_invalid",
			expected: 0,
			found:    false,
		},
		{
			name:     "missing key",
			key:      "missing",
			expected: 0,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				err := os.Setenv(tt.envVar, tt.envValue)
				require.NoError(t, err)
				defer func() {
					err := os.Unsetenv(tt.envVar)
					require.NoError(t, err)
				}()
			}

			value, found := loader.GetInt(tt.key)
			assert.Equal(t, tt.expected, value)
			assert.Equal(t, tt.found, found)
		})
	}
}

func TestEnvConfigLoader_GetIntWithDefault(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"existing": "100",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name         string
		key          string
		defaultValue int
		expected     int
	}{
		{
			name:         "returns existing int value",
			key:          "existing",
			defaultValue: 50,
			expected:     100,
		},
		{
			name:         "returns default for missing key",
			key:          "missing",
			defaultValue: 75,
			expected:     75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := loader.GetIntWithDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvConfigLoader_GetDuration(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"yaml_duration": "5m",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	tests := []struct {
		name     string
		key      string
		envVar   string
		envValue string
		expected string
		found    bool
	}{
		{
			name:     "duration from env",
			key:      "duration.key",
			envVar:   "TEST_DURATION_KEY",
			envValue: "10s",
			expected: "10s",
			found:    true,
		},
		{
			name:     "duration from yaml",
			key:      "yaml_duration",
			expected: "5m",
			found:    true,
		},
		{
			name:     "missing duration",
			key:      "missing",
			expected: "",
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				err := os.Setenv(tt.envVar, tt.envValue)
				require.NoError(t, err)
				defer func() {
					err := os.Unsetenv(tt.envVar)
					require.NoError(t, err)
				}()
			}

			value, found := loader.GetDuration(tt.key)
			assert.Equal(t, tt.expected, value)
			assert.Equal(t, tt.found, found)
		})
	}
}

func TestEnvConfigLoader_GetDurationWithDefault(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	yamlData := map[string]any{
		"existing": "30s",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	result := loader.GetDurationWithDefault("existing", "1m")
	assert.Equal(t, "30s", result)

	result = loader.GetDurationWithDefault("missing", "2m")
	assert.Equal(t, "2m", result)
}

func TestEnvConfigLoader_HasPrefix(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	// Set some test environment variables
	err := os.Setenv("TEST_PREFIX_KEY1", "env_value1")
	require.NoError(t, err)
	err = os.Setenv("TEST_PREFIX_KEY2", "env_value2")
	require.NoError(t, err)
	err = os.Setenv("TEST_OTHER_KEY", "other_value")
	require.NoError(t, err)
	defer func() {
		_ = os.Unsetenv("TEST_PREFIX_KEY1")
		_ = os.Unsetenv("TEST_PREFIX_KEY2")
		_ = os.Unsetenv("TEST_OTHER_KEY")
	}()

	yamlData := map[string]any{
		"prefix": map[string]any{
			"yaml1": "yaml_value1",
			"yaml2": "yaml_value2",
		},
		"other": "other_yaml",
	}

	loader := NewEnvConfigLoader("TEST", yamlData)

	result := loader.HasPrefix("prefix")

	// Should contain both env and yaml values that match the prefix
	expected := map[string]string{
		"prefix.key1":  "env_value1",
		"prefix.key2":  "env_value2",
		"prefix.yaml1": "yaml_value1",
		"prefix.yaml2": "yaml_value2",
	}

	assert.Equal(t, expected, result)
}

func TestEnvConfigLoader_HasPrefix_EdgeCases(t *testing.T) {
	cleanup := setupTestEnv()
	defer cleanup()

	// This test is hard to implement because os.Environ() returns properly formatted env vars
	// The malformed env var case (len(parts) != 2) is extremely rare in practice
	// Most coverage tools will show this line as uncovered, which is acceptable

	loader := NewEnvConfigLoader("TEST", map[string]any{})
	result := loader.HasPrefix("nonexistent")
	assert.Empty(t, result)
}

func TestEnvConfigLoader_buildEnvKey(t *testing.T) {
	tests := []struct {
		name      string
		envPrefix string
		key       string
		expected  string
	}{
		{
			name:      "with prefix and dots",
			envPrefix: "APP",
			key:       "database.host",
			expected:  "APP_DATABASE_HOST",
		},
		{
			name:      "with prefix and dashes",
			envPrefix: "APP",
			key:       "log-level",
			expected:  "APP_LOG_LEVEL",
		},
		{
			name:      "without prefix",
			envPrefix: "",
			key:       "server.port",
			expected:  "SERVER_PORT",
		},
		{
			name:      "mixed separators",
			envPrefix: "TEST",
			key:       "cache.redis-url",
			expected:  "TEST_CACHE_REDIS_URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewEnvConfigLoader(tt.envPrefix, nil)
			result := loader.buildEnvKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvConfigLoader_envKeyToConfigKey(t *testing.T) {
	tests := []struct {
		name      string
		envPrefix string
		envKey    string
		expected  string
	}{
		{
			name:      "with prefix",
			envPrefix: "APP",
			envKey:    "APP_DATABASE_HOST",
			expected:  "database.host",
		},
		{
			name:      "without prefix",
			envPrefix: "",
			envKey:    "SERVER_PORT",
			expected:  "server.port",
		},
		{
			name:      "complex key",
			envPrefix: "TEST",
			envKey:    "TEST_CACHE_REDIS_URL",
			expected:  "cache.redis.url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewEnvConfigLoader(tt.envPrefix, nil)
			result := loader.envKeyToConfigKey(tt.envKey)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvConfigLoader_getFromYAML(t *testing.T) {
	yamlData := map[string]any{
		"simple": "simple_value",
		"nested": map[string]any{
			"key": "nested_value",
			"deep": map[string]any{
				"value": "deep_value",
			},
		},
		"number":     42,
		"int_value":  123,
		"bool_value": true,
	}

	loader := NewEnvConfigLoader("", yamlData)

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "simple key",
			key:      "simple",
			expected: "simple_value",
		},
		{
			name:     "nested key",
			key:      "nested.key",
			expected: "nested_value",
		},
		{
			name:     "deep nested key",
			key:      "nested.deep.value",
			expected: "deep_value",
		},
		{
			name:     "missing key",
			key:      "missing.key",
			expected: "",
		},
		{
			name:     "partial path exists",
			key:      "nested.missing",
			expected: "",
		},
		{
			name:     "integer value converted to string",
			key:      "int_value",
			expected: "123", // This will test the int conversion path
		},
		{
			name:     "empty key",
			key:      "",
			expected: "", // This will test the unreachable return path
		},
		{
			name:     "boolean value not converted",
			key:      "bool_value",
			expected: "", // Non-string, non-int values return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := loader.getFromYAML(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to clean up environment variables
func setupTestEnv() func() {
	// Store original values
	originalVars := make(map[string]string)
	for _, env := range os.Environ() {
		if len(env) > 0 {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && strings.HasPrefix(parts[0], "TEST_") {
				originalVars[parts[0]] = parts[1]
			}
		}
	}

	// Clear test variables
	for key := range originalVars {
		_ = os.Unsetenv(key)
	}

	// Return cleanup function
	return func() {
		// Clear any test vars that might have been set
		for _, env := range os.Environ() {
			if len(env) > 0 {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) >= 1 && strings.HasPrefix(parts[0], "TEST_") {
					_ = os.Unsetenv(parts[0])
				}
			}
		}

		// Restore original values
		for key, value := range originalVars {
			_ = os.Setenv(key, value)
		}
	}
}
