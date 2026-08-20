package oob

import "context"

// Provider is the interface for OOB (Out-of-Band) verification backends.
// Each provider implements DNS/HTTP callback recording and polling.
type Provider interface {
	// Name returns the provider name (e.g. "ceye", "dnslog", "callbackred").
	Name() string
	// CallbackURL returns the callback domain/subdomain for payloads.
	CallbackURL() string
	// Label returns the bare identifier for API queries.
	Label() string
	// Token returns the API token/credentials (may be empty for some providers).
	Token() string
	// VerifyDNS checks if any DNS record was recorded for this label.
	VerifyDNS(ctx context.Context) (bool, error)
	// VerifyHTTP checks if any HTTP request was recorded for this label.
	VerifyHTTP(ctx context.Context) (bool, error)
	// Probe fetches a fresh callback subdomain/credentials from the provider.
	// Must be called before VerifyDNS/VerifyHTTP.
	Probe(ctx context.Context) error
	// Setup configures the provider with external credentials (e.g. ceye label/domain).
	// Not all providers need this (dnslog/callbackred auto-probe).
	Setup(label, domain string)
}

// NewOobProvider creates an OOB provider based on the given configuration.
// provider can be "ceye", "dnslog", "callbackred", or "" (defaults to ceye).
// token is passed through for ceye provider; other providers ignore it.
func NewOobProvider(provider string, token string) Provider {
	switch provider {
	case "dnslog":
		return newDNSLogProvider()
	case "callbackred":
		return newCallbackRedProvider()
	case "", "ceye":
		return newCeyeProvider(token)
	default:
		return newCeyeProvider(token)
	}
}

// DefaultProvider returns the name of the default OOB provider.
func DefaultProvider() string {
	return "ceye"
}
