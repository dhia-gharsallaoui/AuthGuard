package ipwhitelist

import "errors"

// IP whitelist specific errors
var (
	ErrNoAllowedIPs = errors.New("no allowed IPs or CIDRs configured")
)
