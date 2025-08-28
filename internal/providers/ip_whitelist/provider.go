package ipwhitelist

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"authguard/internal/auth"
)

// Provider implements IP whitelist authentication
type Provider struct {
	config      *Config
	logger      auth.Logger
	metrics     auth.Metrics
	cache       auth.Cache
	lockManager auth.LockManager
}

// NewProvider creates a new IP whitelist authentication provider
func NewProvider(cache auth.Cache, lockManager auth.LockManager, logger auth.Logger, metrics auth.Metrics) *Provider {
	return &Provider{
		logger:      logger.With("provider", "ip_whitelist"),
		metrics:     metrics,
		cache:       cache,
		lockManager: lockManager,
	}
}

// Type returns the provider type
func (p *Provider) Type() auth.ProviderType {
	return auth.ProviderTypeIPWhitelist
}

// LoadConfig loads and validates IP whitelist configuration
func (p *Provider) LoadConfig(loader auth.ConfigLoader) error {
	config := &Config{}

	// Load allowed IPs/CIDRs
	allowedIPsStr := loader.GetWithDefault("ip_whitelist.allowed_ips", "127.0.0.1")
	allowedIPs := strings.SplitSeq(allowedIPsStr, ",")

	for ipStr := range allowedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// Parse as CIDR first, then as IP
		if _, cidr, err := net.ParseCIDR(ipStr); err == nil {
			config.AllowedCIDRs = append(config.AllowedCIDRs, cidr)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			config.AllowedIPs = append(config.AllowedIPs, ip)
		} else {
			return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
		}
	}

	// Load proxy headers configuration
	config.ProxyHeader = loader.GetWithDefault("ip_whitelist.proxy_header", "")
	config.TrustedProxies = strings.Split(loader.GetWithDefault("ip_whitelist.trusted_proxies", ""), ",")

	// Clean up trusted proxies
	var validTrustedProxies []string
	for _, proxy := range config.TrustedProxies {
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			validTrustedProxies = append(validTrustedProxies, proxy)
		}
	}
	config.TrustedProxies = validTrustedProxies

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("ip_whitelist config validation failed: %w", err)
	}

	p.config = config
	p.logger.Info("ip_whitelist provider configured",
		"allowed_ips", len(config.AllowedIPs),
		"allowed_cidrs", len(config.AllowedCIDRs))
	return nil
}

// Validate validates IP whitelist authentication from AuthContext
func (p *Provider) Validate(ctx context.Context, authCtx *auth.AuthContext) (*auth.UserClaims, error) {
	start := time.Now()
	defer func() {
		p.metrics.ObserveValidationDuration("ip_whitelist", time.Since(start))
	}()

	p.metrics.IncProviderRequests("ip_whitelist")

	// Note: IP whitelist provider doesn't use caching because:
	// - IP validation is extremely fast (just network checks)
	// - IP addresses can change frequently
	// - No expensive external API calls to cache
	// If needed, caching could be implemented like:
	// cacheKey := "ip_whitelist:" + clientIP
	// p.cache.Get/Set with short TTL

	// Get client IP
	clientIP, err := p.getClientIP(authCtx)
	if err != nil {
		p.logger.Debug("failed to get client IP", "error", err)
		return nil, auth.ErrInvalidToken
	}

	// Check if IP is allowed
	allowed := p.isIPAllowed(clientIP)
	if !allowed {
		p.logger.Debug("IP not in whitelist", "ip", clientIP.String())
		return nil, auth.ErrUnauthorized
	}

	// Create user claims - IP whitelist doesn't provide user info, just authorization
	claims := &auth.UserClaims{
		Subject:   clientIP.String(), // Use IP as subject
		Provider:  auth.ProviderTypeIPWhitelist,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // IP authorization valid for 24h
		CustomClaims: map[string]any{
			"client_ip": clientIP.String(),
			"auth_type": "ip_whitelist",
		},
	}

	p.logger.Debug("IP whitelist validation successful", "ip", clientIP.String())
	return claims, nil
}

// getClientIP extracts the real client IP considering proxy headers
func (p *Provider) getClientIP(authCtx *auth.AuthContext) (net.IP, error) {
	var ipStr string

	// If proxy header is configured, use it
	if p.config.ProxyHeader != "" {
		if proxyIP, exists := authCtx.GetHeader(p.config.ProxyHeader); exists {
			// Validate that the request comes from a trusted proxy
			if p.isTrustedProxy(authCtx.RemoteAddr) {
				ipStr = proxyIP
			} else {
				p.logger.Warn("untrusted proxy attempted to set IP header",
					"proxy", authCtx.RemoteAddr,
					"header", p.config.ProxyHeader)
			}
		}
	}

	// Fallback to RemoteAddr
	if ipStr == "" {
		ipStr = authCtx.RemoteAddr
	}

	// Handle cases like "127.0.0.1:52341"
	if strings.Contains(ipStr, ":") {
		host, _, err := net.SplitHostPort(ipStr)
		if err == nil {
			ipStr = host
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return ip, nil
}

// isTrustedProxy checks if the request comes from a trusted proxy
func (p *Provider) isTrustedProxy(remoteAddr string) bool {
	if len(p.config.TrustedProxies) == 0 {
		return false
	}

	// Extract IP from remoteAddr
	if strings.Contains(remoteAddr, ":") {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return false
		}
		remoteAddr = host
	}

	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, trustedProxy := range p.config.TrustedProxies {
		if _, cidr, err := net.ParseCIDR(trustedProxy); err == nil {
			if cidr.Contains(remoteIP) {
				return true
			}
		} else if ip := net.ParseIP(trustedProxy); ip != nil && ip.Equal(remoteIP) {
			return true
		}
	}

	return false
}

// isIPAllowed checks if the IP is in the whitelist
func (p *Provider) isIPAllowed(ip net.IP) bool {
	// Check exact IP matches
	if slices.ContainsFunc(p.config.AllowedIPs, ip.Equal) {
		return true
	}

	// Check CIDR matches
	for _, cidr := range p.config.AllowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// Health checks the IP whitelist provider's health
func (p *Provider) Health(ctx context.Context) error {
	// IP whitelist provider is always healthy if configured
	if p.config == nil {
		return fmt.Errorf("ip_whitelist provider not configured")
	}
	return nil
}

// Close closes the provider and cleans up resources
func (p *Provider) Close() error {
	// Nothing to clean up for IP whitelist
	return nil
}

// Stats returns IP whitelist provider statistics
func (p *Provider) Stats() any {
	return map[string]any{
		"allowed_ips":     len(p.config.AllowedIPs),
		"allowed_cidrs":   len(p.config.AllowedCIDRs),
		"proxy_header":    p.config.ProxyHeader,
		"trusted_proxies": p.config.TrustedProxies,
	}
}
