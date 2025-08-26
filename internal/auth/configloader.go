package auth

// ConfigLoader provides an abstracted way to load configuration values
type ConfigLoader interface {
	// Get retrieves a configuration value by key
	Get(key string) (string, bool)

	// GetWithDefault retrieves a configuration value with a default fallback
	GetWithDefault(key, defaultValue string) string

	// GetBool retrieves a boolean configuration value
	GetBool(key string) (bool, bool)

	// GetBoolWithDefault retrieves a boolean configuration value with default
	GetBoolWithDefault(key string, defaultValue bool) bool

	// GetInt retrieves an integer configuration value
	GetInt(key string) (int, bool)

	// GetIntWithDefault retrieves an integer configuration value with default
	GetIntWithDefault(key string, defaultValue int) int

	// GetDuration retrieves a duration configuration value (e.g., "10s", "1h")
	GetDuration(key string) (string, bool)

	// GetDurationWithDefault retrieves a duration configuration value with default
	GetDurationWithDefault(key string, defaultValue string) string

	// HasPrefix returns all keys that start with the given prefix
	HasPrefix(prefix string) map[string]string
}
