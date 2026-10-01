package shieldlabs

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// ManagementClient calls the Management API with the Secret Key of one
// registered domain.
//
// The Management API allows about 15 requests per minute per caller IP
// address and then blocks that IP for 10 minutes. Call it sparingly (cache
// the profile) and never in a loop. The client never retries a 429 answer,
// because retrying would only run into the block.
//
// A ManagementClient is safe for concurrent use by multiple goroutines.
type ManagementClient struct {
	t *transport
}

// DomainProfile describes a registered domain.
type DomainProfile struct {
	// Domain is the registered domain.
	Domain string `json:"domain"`
	// RemainingIdentifications is the number of included identifications left
	// on the account. It can be negative when the account is over its
	// included volume.
	RemainingIdentifications int64 `json:"remaining_identifications"`
	// PublicKeyMasked is the public key with every character except the last
	// 4 replaced by "*".
	PublicKeyMasked string `json:"public_key_masked"`
	// SecretKeyMasked is the Secret Key, masked the same way.
	SecretKeyMasked string `json:"secret_key_masked"`
	// CreatedAt is when the domain was registered (UTC), or the zero time
	// when unknown.
	CreatedAt time.Time `json:"created_at"`
	// Raw is the original response object, including fields this model does
	// not cover. Numbers are json.Number values.
	Raw map[string]any `json:"-"`
}

// NewManagementClient returns a Management API client for a Secret Key and
// the domain it was issued for.
//
// The domain is normalized before it is sent, because the API matches the
// registered domain exactly: surrounding spaces, a scheme, a path, a trailing
// slash and a leading "www." are removed and the rest is lowercased, so
// "https://www.Example.com/" becomes "example.com".
//
// It returns an error matching [ErrValidation] when the secret key or the
// domain is empty or contains whitespace or control characters (surrounding
// whitespace is trimmed), or when an option is invalid. Defaults: base URL
// [DefaultManagementBaseURL], a 10-second timeout per HTTP attempt and 2
// retries (never on 429).
func NewManagementClient(secretKey, domain string, opts ...Option) (*ManagementClient, error) {
	secret := strings.TrimSpace(secretKey)
	if secret == "" {
		return nil, validationError("the Secret Key is empty")
	}
	if hasSpaceOrControl(secret) {
		return nil, validationError("the Secret Key contains whitespace or control characters: copy it again")
	}
	d := normalizeDomain(domain)
	if d == "" {
		return nil, validationError("the domain is empty: pass the domain registered for this Secret Key")
	}
	if hasSpaceOrControl(d) {
		return nil, validationError("the domain contains whitespace or control characters: pass the domain registered for this Secret Key")
	}
	cfg := newConfig(DefaultManagementBaseURL, opts)
	if cfg.err != nil {
		return nil, cfg.err
	}
	base, err := normalizeBaseURL(cfg.baseURL, false, cfg)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+secret)
	header.Set("X-Shield-Domain", d)
	return &ManagementClient{t: newTransport(base, cfg, header)}, nil
}

// GetProfile returns the profile of the client's domain (GET /v1/profile).
// An exhausted account answers with an error matching [ErrQuotaExceeded], a
// wrong secret or domain with [ErrAuthentication] and the per-IP limit with
// [ErrRateLimited].
func (m *ManagementClient) GetProfile(ctx context.Context) (*DomainProfile, error) {
	resp, err := m.t.get(ctx, apiRequest{path: "/v1/profile", retry429: false})
	if err != nil {
		return nil, err
	}
	body, err := wire.DecodeObject(resp.body)
	if err != nil {
		return nil, &APIError{
			StatusCode: resp.status,
			Message:    "the response is not a domain profile: " + err.Error(),
			Body:       resp.body,
			Header:     resp.header,
		}
	}
	createdAt, _ := wire.ParseRFC3339(str(body["CreatedAt"]))
	return &DomainProfile{
		Domain:                   str(body["Domain"]),
		RemainingIdentifications: toInt64(body["Weight"]),
		PublicKeyMasked:          str(body["PublicKey"]),
		SecretKeyMasked:          str(body["Secret"]),
		CreatedAt:                createdAt,
		Raw:                      body,
	}, nil
}

// normalizeDomain turns a domain or URL into the bare registered domain:
// trimmed, lowercased, without scheme, path, query, fragment, trailing slash
// or leading "www.".
func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimPrefix(d, "www.")
	return strings.TrimSpace(d)
}
