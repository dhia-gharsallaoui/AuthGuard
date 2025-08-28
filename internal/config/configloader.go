package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnvConfigLoader implements ConfigLoader using environment variables and YAML
type EnvConfigLoader struct {
	envPrefix string
	yamlData  map[string]any
}

// NewEnvConfigLoader creates a new environment-based config loader
func NewEnvConfigLoader(envPrefix string, yamlData map[string]any) *EnvConfigLoader {
	if yamlData == nil {
		yamlData = make(map[string]any)
	}

	return &EnvConfigLoader{
		envPrefix: envPrefix,
		yamlData:  yamlData,
	}
}

// Get retrieves a configuration value by key
func (e *EnvConfigLoader) Get(key string) (string, bool) {
	// Try environment variable first (with prefix)
	envKey := e.buildEnvKey(key)
	if value := os.Getenv(envKey); value != "" {
		return value, true
	}

	// Try YAML data
	if value := e.getFromYAML(key); value != "" {
		return value, true
	}

	return "", false
}

// GetWithDefault retrieves a configuration value with a default fallback
func (e *EnvConfigLoader) GetWithDefault(key, defaultValue string) string {
	if value, ok := e.Get(key); ok {
		return value
	}
	return defaultValue
}

// GetBool retrieves a boolean configuration value
func (e *EnvConfigLoader) GetBool(key string) (bool, bool) {
	value, ok := e.Get(key)
	if !ok {
		return false, false
	}

	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return false, false
	}

	return boolValue, true
}

// GetBoolWithDefault retrieves a boolean configuration value with default
func (e *EnvConfigLoader) GetBoolWithDefault(key string, defaultValue bool) bool {
	if value, ok := e.GetBool(key); ok {
		return value
	}
	return defaultValue
}

// GetInt retrieves an integer configuration value
func (e *EnvConfigLoader) GetInt(key string) (int, bool) {
	value, ok := e.Get(key)
	if !ok {
		return 0, false
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}

	return intValue, true
}

// GetIntWithDefault retrieves an integer configuration value with default
func (e *EnvConfigLoader) GetIntWithDefault(key string, defaultValue int) int {
	if value, ok := e.GetInt(key); ok {
		return value
	}
	return defaultValue
}

// GetDuration retrieves a duration configuration value
func (e *EnvConfigLoader) GetDuration(key string) (string, bool) {
	return e.Get(key)
}

// GetDurationWithDefault retrieves a duration configuration value with default
func (e *EnvConfigLoader) GetDurationWithDefault(key string, defaultValue string) string {
	return e.GetWithDefault(key, defaultValue)
}

// HasPrefix returns all keys that start with the given prefix
func (e *EnvConfigLoader) HasPrefix(prefix string) map[string]string {
	result := make(map[string]string)

	// Check environment variables
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		envKey := parts[0]
		if strings.HasPrefix(envKey, e.buildEnvKey(prefix)) {
			// Convert back to config key format
			configKey := e.envKeyToConfigKey(envKey)
			result[configKey] = parts[1]
		}
	}

	// Check YAML data
	e.collectYAMLWithPrefix(prefix, "", e.yamlData, result)

	return result
}

// buildEnvKey builds an environment variable key from a config key
func (e *EnvConfigLoader) buildEnvKey(key string) string {
	// Convert dots and dashes to underscores and make uppercase
	envKey := strings.ReplaceAll(key, ".", "_")
	envKey = strings.ReplaceAll(envKey, "-", "_")
	envKey = strings.ToUpper(envKey)

	if e.envPrefix != "" {
		return e.envPrefix + "_" + envKey
	}

	return envKey
}

// envKeyToConfigKey converts an environment variable key back to config key format
func (e *EnvConfigLoader) envKeyToConfigKey(envKey string) string {
	configKey := envKey

	// Remove prefix if present
	if e.envPrefix != "" && strings.HasPrefix(configKey, e.envPrefix+"_") {
		configKey = strings.TrimPrefix(configKey, e.envPrefix+"_")
	}

	// Convert to lowercase and replace underscores with dots
	configKey = strings.ToLower(configKey)
	configKey = strings.ReplaceAll(configKey, "_", ".")

	return configKey
}

// getFromYAML retrieves a value from YAML data using dot notation
func (e *EnvConfigLoader) getFromYAML(key string) string {
	parts := strings.Split(key, ".")
	current := e.yamlData

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - get the value
			if value, ok := current[part]; ok {
				if strValue, ok := value.(string); ok {
					return strValue
				}
				// Try to convert other types to string
				if intValue, ok := value.(int); ok {
					return fmt.Sprintf("%d", intValue)
				}
			}
			return ""
		}

		// Navigate deeper into the structure
		if next, ok := current[part].(map[string]any); ok {
			current = next
		} else {
			return ""
		}
	}
	// This should never be reached, but required by Go
	return ""
}

// collectYAMLWithPrefix collects all YAML keys with a given prefix
func (e *EnvConfigLoader) collectYAMLWithPrefix(prefix, currentPath string, data map[string]any, result map[string]string) {
	for key, value := range data {
		fullPath := key
		if currentPath != "" {
			fullPath = currentPath + "." + key
		}

		if strings.HasPrefix(fullPath, prefix) {
			if strValue, ok := value.(string); ok {
				result[fullPath] = strValue
			}
		}

		// Recurse into nested maps
		if nested, ok := value.(map[string]any); ok {
			e.collectYAMLWithPrefix(prefix, fullPath, nested, result)
		}
	}
}
