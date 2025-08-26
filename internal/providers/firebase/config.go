package firebase

// Config holds Firebase configuration matching your existing implementation
type Config struct {
	ProjectID         string `yaml:"project_id"`
	CredentialsPath   string `yaml:"credentials_path"`
	CredentialsBase64 string `yaml:"credentials_base64"`
}

// Validate validates the Firebase configuration
func (c *Config) Validate() error {
	if c.ProjectID == "" {
		return ErrMissingProjectID
	}
	return nil
}
