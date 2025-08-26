package ipwhitelist

import (
	"net"
)

// Config holds IP whitelist configuration
type Config struct {
	AllowedIPs     []net.IP     `yaml:"allowed_ips"`
	AllowedCIDRs   []*net.IPNet `yaml:"allowed_cidrs"`
	ProxyHeader    string       `yaml:"proxy_header"`    // Header to read real IP from (e.g., "X-Real-IP", "X-Forwarded-For")
	TrustedProxies []string     `yaml:"trusted_proxies"` // IPs/CIDRs of trusted proxies
}

// Validate validates the IP whitelist configuration
func (c *Config) Validate() error {
	if len(c.AllowedIPs) == 0 && len(c.AllowedCIDRs) == 0 {
		return ErrNoAllowedIPs
	}
	return nil
}
