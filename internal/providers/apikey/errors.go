package apikey

import "errors"

var (
	// ErrMissingAPIKey indicates that no API key was provided
	ErrMissingAPIKey = errors.New("missing API key")

	// ErrInvalidAPIKey indicates that the provided API key is invalid
	ErrInvalidAPIKey = errors.New("invalid API key")

	// ErrAPIKeyNotFound indicates that the API key was not found in configuration
	ErrAPIKeyNotFound = errors.New("API key not found")
)
