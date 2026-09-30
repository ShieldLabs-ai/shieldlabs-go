package shieldlabs

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const (
	defaultTimeout    = 10 * time.Second
	defaultMaxRetries = 2
)

// Option configures a [Client] or a [ManagementClient].
type Option func(*config)

type config struct {
	baseURL           string
	allowInsecureHTTP bool
	httpClient        *http.Client
	timeout           time.Duration
	maxRetries        int
	logger            *slog.Logger
	err               error
}

func newConfig(defaultBaseURL string, opts []Option) *config {
	cfg := &config{
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.httpClient == nil {
		cfg.httpClient = &http.Client{}
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	return cfg
}

// WithBaseURL overrides the API origin, for example
// "https://dev.account.shieldlabs.ai" for the History API or a local test
// server. A trailing slash is removed. For the History client a trailing
// "/api" is removed too, because request paths already start with /api.
//
// An empty value keeps the default, so an optional override can be passed
// straight from the environment:
//
//	shieldlabs.WithBaseURL(os.Getenv("SHIELDLABS_API_BASE_URL"))
//
// The URL must use https. Plain http is accepted for localhost, 127.0.0.0/8
// and [::1], and for other hosts only together with [WithInsecureHTTP].
func WithBaseURL(baseURL string) Option {
	return func(c *config) {
		if strings.TrimSpace(baseURL) != "" {
			c.baseURL = baseURL
		}
	}
}

// WithInsecureHTTP accepts a plain http base URL on a host other than
// localhost, 127.0.0.0/8 or [::1], for example a mock server in a container
// network. Keys then travel unencrypted, so never use it in production; the
// client logs a warning when it is created with such a URL.
func WithInsecureHTTP() Option {
	return func(c *config) { c.allowInsecureHTTP = true }
}

// WithHTTPClient sets the *http.Client used for requests, for example to
// configure a proxy or a custom transport. The default is a new http.Client
// that uses http.DefaultTransport.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout sets the timeout of each HTTP attempt (default 10 seconds). Zero
// disables the per-attempt timeout; the request context still applies.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d < 0 {
			c.err = validationError("the timeout must not be negative")
			return
		}
		c.timeout = d
	}
}

// WithMaxRetries sets how many times a failed request is retried (default 2).
// Zero disables retries.
func WithMaxRetries(n int) Option {
	return func(c *config) {
		if n < 0 {
			c.err = validationError("the number of retries must not be negative")
			return
		}
		c.maxRetries = n
	}
}

// WithLogger sets the logger used for configuration warnings, for example a
// Private API Key with an unexpected format. The default is slog.Default().
// The SDK never logs keys, secrets or response bodies.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// hasSpaceOrControl reports whether s contains whitespace or a control
// character. Keys, secrets and domains never do; such a value usually comes
// from a bad copy and paste, and would be rejected as an HTTP header value.
func hasSpaceOrControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0
}
