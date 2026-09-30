package shieldlabs

import (
	"net/http"
	"regexp"
	"strings"
)

var privateAPIKeyRE = regexp.MustCompile(`^sec_[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}$`)

// Client reads identifications from the History API with a Private API Key
// (sec_...). Each Private API Key reads the identifications of one domain.
//
// A Client is safe for concurrent use by multiple goroutines. Create it once
// and reuse it.
type Client struct {
	// Identifications reads one identification by its request ID.
	Identifications *IdentificationsService
	// History searches identifications by device, user, visitor, IP address,
	// session, cookie or request ID.
	History *HistoryService

	t *transport
}

// NewClient returns a History API client for the given Private API Key.
//
// It returns an error matching [ErrValidation] when the key is empty or
// contains whitespace or control characters (surrounding whitespace is
// trimmed), or when an option is invalid. A key that does not look like a
// Private API Key (sec_xxxxxxxx-xxxxxxxx-xxxxxxxx) only produces a warning on
// the configured logger, because the key format may change.
//
// Defaults: base URL [DefaultBaseURL], a 10-second timeout per HTTP attempt
// and 2 retries.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return nil, validationError("the API key is empty: pass the Private API Key (sec_...) of your domain")
	}
	if hasSpaceOrControl(key) {
		return nil, validationError("the API key contains whitespace or control characters: copy the Private API Key (sec_...) again")
	}
	cfg := newConfig(DefaultBaseURL, opts)
	if cfg.err != nil {
		return nil, cfg.err
	}
	base, err := normalizeBaseURL(cfg.baseURL, true, cfg)
	if err != nil {
		return nil, err
	}
	if !privateAPIKeyRE.MatchString(key) {
		cfg.logger.Warn("shieldlabs: the API key does not look like a Private API Key (sec_xxxxxxxx-xxxxxxxx-xxxxxxxx); the History API expects the Private API Key of your domain, not the public key or the Secret Key")
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+key)
	c := &Client{t: newTransport(base, cfg, header)}
	c.History = &HistoryService{c: c}
	c.Identifications = &IdentificationsService{c: c}
	return c, nil
}
