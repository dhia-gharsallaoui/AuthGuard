package auth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testTime = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func TestCacheType_String(t *testing.T) {
	tests := []struct {
		name      string
		cacheType CacheType
		expected  string
	}{
		{
			name:      "Memory cache",
			cacheType: CacheTypeMemory,
			expected:  "memory",
		},
		{
			name:      "Redis cache",
			cacheType: CacheTypeRedis,
			expected:  "redis",
		},
		{
			name:      "Unknown cache type",
			cacheType: CacheType(999),
			expected:  "memory", // defaults to memory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cacheType.String())
		})
	}
}

func TestParseCacheType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CacheType
	}{
		{
			name:     "Parse memory",
			input:    "memory",
			expected: CacheTypeMemory,
		},
		{
			name:     "Parse redis",
			input:    "redis",
			expected: CacheTypeRedis,
		},
		{
			name:     "Parse unknown",
			input:    "invalid",
			expected: CacheTypeMemory, // defaults to memory
		},
		{
			name:     "Parse empty string",
			input:    "",
			expected: CacheTypeMemory, // defaults to memory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseCacheType(tt.input))
		})
	}
}

func TestCacheType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		cacheType CacheType
		expected  string
	}{
		{
			name:      "Marshal memory",
			cacheType: CacheTypeMemory,
			expected:  `"memory"`,
		},
		{
			name:      "Marshal redis",
			cacheType: CacheTypeRedis,
			expected:  `"redis"`,
		},
		{
			name:      "Marshal unknown",
			cacheType: CacheType(999),
			expected:  `"memory"`, // defaults to memory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := tt.cacheType.MarshalJSON()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(jsonBytes))
		})
	}
}

func TestCacheType_JSONMarshalUnmarshal(t *testing.T) {
	// Test that we can marshal and unmarshal CacheType in structs
	type TestStruct struct {
		CacheType CacheType `json:"cache_type"`
		Name      string    `json:"name"`
	}

	original := TestStruct{
		CacheType: CacheTypeRedis,
		Name:      "test",
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	assert.NoError(t, err)

	// Should contain the string representation
	assert.Contains(t, string(jsonData), `"redis"`)

	// Note: Unmarshaling would require implementing UnmarshalJSON
	// which is not implemented in the current code, so we don't test it
}

func TestCacheStats_Structure(t *testing.T) {
	// Test that CacheStats can be created and marshaled
	stats := CacheStats{
		Hits:        100,
		Misses:      10,
		Keys:        50,
		Type:        CacheTypeMemory,
		LastUpdated: testTime,
	}

	// Should be able to marshal to JSON
	jsonData, err := json.Marshal(stats)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), `"hits":100`)
	assert.Contains(t, string(jsonData), `"misses":10`)
	assert.Contains(t, string(jsonData), `"keys":50`)
	assert.Contains(t, string(jsonData), `"memory"`)

	// Note: CacheType doesn't implement UnmarshalJSON, so we can only check marshaling
	// If we wanted to test full round-trip, we'd need to implement UnmarshalJSON for CacheType
}

func TestCacheType_Constants(t *testing.T) {
	// Ensure the constants have expected values
	assert.Equal(t, CacheType(0), CacheTypeMemory)
	assert.Equal(t, CacheType(1), CacheTypeRedis)

	// Ensure they're different
	assert.NotEqual(t, CacheTypeMemory, CacheTypeRedis)
}

func TestCacheType_RoundTrip(t *testing.T) {
	// Test round-trip conversion: CacheType -> String -> CacheType
	originalTypes := []CacheType{
		CacheTypeMemory,
		CacheTypeRedis,
	}

	for _, original := range originalTypes {
		str := original.String()
		parsed := ParseCacheType(str)
		assert.Equal(t, original, parsed, "Round-trip conversion should preserve cache type")
	}
}
