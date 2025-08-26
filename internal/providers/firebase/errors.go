package firebase

import "errors"

// Firebase provider specific errors
var (
	ErrMissingProjectID = errors.New("firebase project ID is required")
)
