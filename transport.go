package shieldlabs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	backoffBase       = 500 * time.Millisecond
	backoffCap        = 8 * time.Second
	maxRetryAfter     = 10 * time.Second
	minRateLimitDelay = time.Second // the History limit counts per one-second window
	maxResponseBytes  = 32 << 20
)

// clock abstracts time so that tests can run retry and polling schedules
// without waiting.
type clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// transport sends GET requests to one API host with retries. It is
// immutable after construction and safe for concurrent use.
type transport struct {
	baseURL    string // scheme://host[/prefix], no trailing slash
	header     http.Header
	httpClient *http.Client
	timeout    time.Duration
	maxRetries int
	clock      clock
	jitter     func() float64 // uniform in [0, 1)
}

func newTransport(baseURL string, cfg *config, header http.Header) *transport {
	header.Set("Accept", "application/json")
	header.Set("User-Agent", userAgent())
	return &transport{
		baseURL:    baseURL,
		header:     header,
		httpClient: cfg.httpClient,
		timeout:    cfg.timeout,
		maxRetries: cfg.maxRetries,
		clock:      realClock{},
		jitter:     rand.Float64,
	}
}

// normalizeBaseURL validates a base URL and removes a trailing slash, plus a
// trailing "/api" segment when stripAPI is set.
//
// The URL must use https, because every request carries a key. Plain http is
// accepted for loopback hosts (local mock servers) and, with
// cfg.allowInsecureHTTP, for any host; the latter logs a warning.
func normalizeBaseURL(raw string, stripAPI bool, cfg *config) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" {
		return "", validationError("the base URL must be an absolute https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", validationError("the base URL must not contain credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		if !cfg.allowInsecureHTTP {
			return "", validationError("the base URL must use https, because every request carries a key; plain http is accepted only for localhost, 127.0.0.0/8 and [::1] (WithInsecureHTTP allows it for a test server on another host)")
		}
		cfg.logger.Warn("shieldlabs: the base URL uses plain http, so the key travels unencrypted; use https outside local tests")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if stripAPI {
		path = strings.TrimRight(strings.TrimSuffix(path, "/api"), "/")
	}
	return u.Scheme + "://" + u.Host + path, nil
}

// isLoopbackHost reports whether a URL host name (without port or brackets)
// is localhost, a name under .localhost or a loopback IP address
// (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// apiRequest describes one GET call.
type apiRequest struct {
	path     string // escaped path, starting with "/"
	query    url.Values
	retry429 bool
	// once sends a single attempt without retries, limited by attemptTimeout
	// instead of the client's timeout (0 means no attempt timeout).
	once           bool
	attemptTimeout time.Duration
}

type apiResponse struct {
	status int
	header http.Header
	body   []byte
}

// get performs a GET request with retries: connection failures, timeouts,
// 5xx responses and (when allowed) 429 responses are retried up to
// maxRetries times with exponential backoff and jitter. A request with once
// set is sent exactly once.
func (t *transport) get(ctx context.Context, r apiRequest) (*apiResponse, error) {
	target := t.baseURL + r.path
	if len(r.query) > 0 {
		target += "?" + r.query.Encode()
	}
	timeout, retries := t.timeout, t.maxRetries
	if r.once {
		timeout, retries = r.attemptTimeout, 0
	}
	for attempt := 0; ; attempt++ {
		resp, err := t.attempt(ctx, target, timeout)
		if err == nil {
			if resp.status >= 200 && resp.status <= 299 {
				return resp, nil
			}
			err = newAPIError(resp.status, resp.header, resp.body, time.Now())
		}
		if ctx.Err() != nil {
			return nil, contextError(ctx, err)
		}
		if attempt >= retries || !t.retryable(err, r) {
			return nil, err
		}
		if serr := t.clock.Sleep(ctx, t.retryDelay(attempt, err)); serr != nil {
			return nil, contextError(ctx, err)
		}
	}
}

// attempt performs one HTTP exchange and reads the whole body. A positive
// timeout limits the whole exchange.
func (t *transport) attempt(ctx context.Context, target string, timeout time.Duration) (*apiResponse, error) {
	actx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(actx, http.MethodGet, target, nil)
	if err != nil {
		return nil, validationError("cannot build the request URL: %v", err)
	}
	for key, values := range t.header {
		req.Header[key] = append([]string(nil), values...)
	}
	res, err := t.httpClient.Do(req)
	if err != nil {
		return nil, networkError(ctx, actx, timeout, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, networkError(ctx, actx, timeout, err)
	}
	if len(body) > maxResponseBytes {
		return nil, &APIError{StatusCode: res.StatusCode, Message: "response body too large", Header: res.Header}
	}
	return &apiResponse{status: res.StatusCode, header: res.Header, body: body}, nil
}

// networkError classifies a transport failure as a timeout or a connection
// error. A cancelled caller context is returned as is (see get).
func networkError(parent, attemptCtx context.Context, timeout time.Duration, err error) error {
	if parent.Err() != nil {
		return err
	}
	if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: no response within %s: %w", ErrTimeout, timeout, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return fmt.Errorf("%w: %w", ErrConnection, err)
}

// retryable reports whether a failed attempt may be repeated.
func (t *transport) retryable(err error, r apiRequest) bool {
	if errors.Is(err, ErrConnection) || errors.Is(err, ErrTimeout) {
		return true
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch {
	case apiErr.StatusCode == http.StatusTooManyRequests:
		return r.retry429
	case apiErr.StatusCode >= 500 && apiErr.StatusCode <= 599:
		return true
	}
	return false
}

// retryDelay returns the wait before retry number attempt+1. A valid
// Retry-After header is followed as sent, capped at 10 seconds, so
// "Retry-After: 0" and a date in the past retry at once. Otherwise the wait is
// exponential backoff (0.5 s doubling up to 8 s) randomized between half and
// the full value, and at least one second after a 429, because the History
// limit counts requests per one-second window. Only the wait of
// Identifications.Get raises every delay after a 429 to at least one second.
func (t *transport) retryDelay(attempt int, err error) time.Duration {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return backoffDelay(attempt, t.jitter())
	}
	if apiErr.retryAfterSent {
		return min(apiErr.RetryAfter, maxRetryAfter)
	}
	d := backoffDelay(attempt, t.jitter())
	if apiErr.StatusCode == http.StatusTooManyRequests {
		d = max(d, minRateLimitDelay)
	}
	return d
}

// backoffDelay computes exponential backoff with "equal jitter": the delay
// for attempt n is between half and all of min(8 s, 0.5 s * 2^n).
func backoffDelay(attempt int, jitter float64) time.Duration {
	d := backoffCap
	if attempt < 5 {
		d = min(backoffCap, backoffBase<<attempt)
	}
	half := d / 2
	return half + time.Duration(jitter*float64(d-half))
}

// contextError reports that the caller's context ended, mentioning the last
// failure when there was one.
func contextError(ctx context.Context, last error) error {
	cause := ctx.Err()
	if last == nil || errors.Is(last, cause) {
		return fmt.Errorf("shieldlabs: %w", cause)
	}
	return fmt.Errorf("shieldlabs: %w (last attempt: %v)", cause, last)
}
