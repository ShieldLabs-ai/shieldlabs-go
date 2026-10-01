package shieldlabs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryHonoursRetryAfterWithCap(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1:
			w.Header().Set("Retry-After", "2")
			writeJSON(w, 503, `{"error":"server is busy"}`)
		case 2:
			w.Header().Set("Retry-After", "120")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 3:
			w.Header().Set("Retry-After", "99999999")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		default:
			writeJSON(w, 200, emptyPage)
		}
	})
	c, clk := newTestClient(t, srv.URL, WithMaxRetries(3))
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := clk.Sleeps(), []time.Duration{2 * time.Second, 10 * time.Second, 10 * time.Second}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
}

func TestRetryFollowsTheRetryAfterDelayAsSent(t *testing.T) {
	// Search and All wait for the delay Retry-After asks for, as sent and even
	// below one second: "Retry-After: 0" and a date in the past retry at once,
	// after a 429 and after a 5xx. Only the wait of Identifications.Get raises
	// every delay after a 429 to at least one second.
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1:
			w.Header().Set("Retry-After", "0.2")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 2:
			w.Header().Set("Retry-After", "0")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 3:
			w.Header().Set("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 4:
			w.Header().Set("Retry-After", "0")
			writeJSON(w, 503, `{"error":"server is busy"}`)
		default:
			writeJSON(w, 200, emptyPage)
		}
	})
	c, clk := newTestClient(t, srv.URL, WithMaxRetries(4))
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := clk.Sleeps(), ms(200, 0, 0, 0); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
	if srv.Count() != 5 {
		t.Errorf("requests = %d, want 5", srv.Count())
	}
}

func TestRateLimitWithoutRetryAfterWaitsAtLeastOneSecond(t *testing.T) {
	// A 429 without Retry-After, or with a value that is no delay (a negative
	// number, text), raises the backoff (250 ms, 500 ms and 1 s with the test
	// jitter) to one second; a longer backoff (2 s) is kept. A 5xx without
	// Retry-After keeps the plain backoff.
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1, 4:
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 2:
			w.Header().Set("Retry-After", "-1")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		case 3:
			w.Header().Set("Retry-After", "soon")
			writeJSON(w, 429, `{"error":"too many requests"}`)
		default:
			writeJSON(w, 200, emptyPage)
		}
	})
	c, clk := newTestClient(t, srv.URL, WithMaxRetries(4))
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := clk.Sleeps(), ms(1000, 1000, 1000, 2000); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", got, want)
	}

	srv5xx := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			writeJSON(w, 503, `{"error":"server is busy"}`)
			return
		}
		writeJSON(w, 200, emptyPage)
	})
	c5xx, clk5xx := newTestClient(t, srv5xx.URL)
	if _, err := c5xx.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := clk5xx.Sleeps(), ms(250); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("5xx waits = %v, want %v", got, want)
	}
}

func TestRetryLimits(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 500, `{"error":"internal error"}`)
	})
	c, clk := newTestClient(t, srv.URL, WithMaxRetries(4))
	_, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil)
	if !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if srv.Count() != 5 {
		t.Errorf("requests = %d, want 5", srv.Count())
	}
	if got, want := clk.Sleeps(), ms(250, 500, 1000, 2000); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", got, want)
	}

	srv2 := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 500, `{"error":"internal error"}`)
	})
	c2, _ := newTestClient(t, srv2.URL, WithMaxRetries(0))
	if _, err := c2.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if srv2.Count() != 1 {
		t.Errorf("WithMaxRetries(0): requests = %d", srv2.Count())
	}
}

func TestBackoffDelayBounds(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		full := min(backoffCap, backoffBase*time.Duration(1<<min(attempt, 5)))
		lo, hi := backoffDelay(attempt, 0), backoffDelay(attempt, 0.999999)
		if lo != full/2 || hi > full || hi < full*99/100 {
			t.Errorf("attempt %d: delay range [%s, %s], full %s", attempt, lo, hi, full)
		}
	}
	c, _ := NewClient(testAPIKey)
	for i := 0; i < 100; i++ {
		if d := c.t.retryDelay(1, errors.New("x")); d < 500*time.Millisecond || d > time.Second {
			t.Fatalf("random jitter out of range: %s", d)
		}
	}
}

func TestConnectionErrorsAreRetried(t *testing.T) {
	var attempts atomic.Int32
	c, err := NewClient(testAPIKey, WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, errors.New("connection reset by peer")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	c.t.clock = newFakeClock()
	_, err = c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil)
	if !errors.Is(err, ErrConnection) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestAttemptTimeoutIsRetried(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	c, clk := newTestClient(t, srv.URL, WithTimeout(30*time.Millisecond))
	_, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil)
	if !errors.Is(err, ErrTimeout) || errors.Is(err, ErrConnection) {
		t.Fatalf("err = %v", err)
	}
	if srv.Count() != 3 || len(clk.Sleeps()) != 2 {
		t.Errorf("requests = %d, waits = %v", srv.Count(), clk.Sleeps())
	}
}

func TestRealClockSleep(t *testing.T) {
	var clk realClock
	if err := clk.Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := clk.Sleep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, d := range []time.Duration{0, time.Hour} {
		if err := clk.Sleep(ctx, d); !errors.Is(err, context.Canceled) {
			t.Errorf("sleep %s: err = %v", d, err)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestNetworkTimeoutFromTransport(t *testing.T) {
	c, err := NewClient(testAPIKey, WithMaxRetries(0), WithTimeout(0), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, timeoutError{}
	})}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestBodyReadErrorIsAConnectionError(t *testing.T) {
	c, err := NewClient(testAPIKey, WithMaxRetries(1), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: failingBody{}, Request: r}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	c.t.clock = newFakeClock()
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); !errors.Is(err, ErrConnection) {
		t.Fatalf("err = %v", err)
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("unexpected EOF") }
func (failingBody) Close() error             { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestContextCancellationIsNotRetried(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 503, `{"error":"server is busy"}`)
	})
	c, _ := newTestClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	c.t.clock = &cancellingClock{fakeClock: newFakeClock(), cancel: cancel}
	_, err := c.History.Search(ctx, LookupDeviceID, NilUUID, nil)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("the last failure should be mentioned: %v", err)
	}
	if srv.Count() != 1 {
		t.Errorf("requests = %d", srv.Count())
	}

	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	_, err = c.History.Search(done, LookupDeviceID, NilUUID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if err.Error() != "shieldlabs: context canceled" {
		t.Errorf("err = %q", err)
	}
}

func TestBaseURLRules(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	tests := []struct {
		base string
		path string
	}{
		{srv.URL, "/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/", "/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/api", "/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/api/", "/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/api//", "/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/proxy", "/proxy/api/v1/history/device_id/" + NilUUID},
		{srv.URL + "/proxy/api", "/proxy/api/v1/history/device_id/" + NilUUID},
		{" " + srv.URL + "/apix ", "/apix/api/v1/history/device_id/" + NilUUID},
	}
	for i, tc := range tests {
		c, _ := newTestClient(t, tc.base)
		if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		if got := srv.Request(i).URL.EscapedPath(); got != tc.path {
			t.Errorf("base %q: path %s, want %s", tc.base, got, tc.path)
		}
	}
	for _, bad := range []string{
		"account.shieldlabs.ai", "ftp://account.shieldlabs.ai", "https://", "https://:443",
		"https://user:pass@account.shieldlabs.ai", "https://account.shieldlabs.ai/?x=1",
		"https://account.shieldlabs.ai/#top", "http://[::1",
		// Plain http outside loopback hosts would send the key unencrypted.
		"http://account.shieldlabs.ai", "HTTP://account.shieldlabs.ai/api", "http://192.0.2.10:8080",
		"http://10.0.0.1", "http://[2001:db8::1]:8080", "http://localhost.example.com",
	} {
		if _, err := NewClient(testAPIKey, WithBaseURL(bad)); !errors.Is(err, ErrValidation) {
			t.Errorf("base URL %q: err = %v", bad, err)
		}
	}
}

func TestBaseURLPlainHTTPOnLoopbackOnly(t *testing.T) {
	for _, base := range []string{
		"http://localhost:8080", "http://LOCALHOST", "http://api.localhost:3000", "http://localhost.:8080",
		"http://127.0.0.1:1", "http://127.8.9.10", "http://[::1]:8080",
	} {
		c, err := NewClient(testAPIKey, WithBaseURL(base), WithLogger(discardLogger()))
		if err != nil {
			t.Errorf("base URL %q: %v", base, err)
			continue
		}
		if !strings.HasPrefix(c.t.baseURL, "http://") {
			t.Errorf("base URL %q became %q", base, c.t.baseURL)
		}
	}

	// WithInsecureHTTP accepts another host, with a warning that never
	// contains the key.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c, err := NewClient(testAPIKey, WithBaseURL("http://192.0.2.10:8080/api"), WithInsecureHTTP(), WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	if c.t.baseURL != "http://192.0.2.10:8080" {
		t.Errorf("base URL = %q", c.t.baseURL)
	}
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "plain http") || strings.Contains(out, testAPIKey) {
		t.Errorf("warning = %q", out)
	}
	m, err := NewManagementClient(testSecretKey, "example.com", WithBaseURL("http://mock:8080"), WithInsecureHTTP(), WithLogger(discardLogger()))
	if err != nil || m.t.baseURL != "http://mock:8080" {
		t.Errorf("Management client: %v", err)
	}

	// Loopback and https URLs never warn.
	buf.Reset()
	for _, base := range []string{"http://127.0.0.1:8080", "https://account.shieldlabs.ai"} {
		if _, err := NewClient(testAPIKey, WithBaseURL(base), WithInsecureHTTP(), WithLogger(logger)); err != nil {
			t.Fatal(err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected warning: %s", buf.String())
	}
}

func TestEmptyBaseURLKeepsTheDefault(t *testing.T) {
	for _, base := range []string{"", "   ", "\n"} {
		c, err := NewClient(testAPIKey, WithBaseURL(base))
		if err != nil {
			t.Fatalf("History base URL %q: %v", base, err)
		}
		if c.t.baseURL != DefaultBaseURL {
			t.Errorf("History base URL %q became %q", base, c.t.baseURL)
		}
		m, err := NewManagementClient(testSecretKey, "example.com", WithBaseURL(base))
		if err != nil {
			t.Fatalf("Management base URL %q: %v", base, err)
		}
		if m.t.baseURL != DefaultManagementBaseURL {
			t.Errorf("Management base URL %q became %q", base, m.t.baseURL)
		}
	}
	// A later non-empty value still wins, and an empty one does not reset it.
	c, err := NewClient(testAPIKey, WithBaseURL("https://dev.account.shieldlabs.ai/api/"), WithBaseURL(""))
	if err != nil || c.t.baseURL != "https://dev.account.shieldlabs.ai" {
		t.Errorf("base URL = %v, %v", c, err)
	}
}

func TestDefaultBaseURLs(t *testing.T) {
	c, err := NewClient(testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.t.baseURL != "https://account.shieldlabs.ai" {
		t.Errorf("History base URL = %s", c.t.baseURL)
	}
	m, err := NewManagementClient(testSecretKey, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if m.t.baseURL != "https://api.shieldlabs.ai" {
		t.Errorf("Management base URL = %s", m.t.baseURL)
	}
	if c.t.timeout != 10*time.Second || c.t.maxRetries != 2 || m.t.timeout != 10*time.Second || m.t.maxRetries != 2 {
		t.Error("defaults: 10 s per attempt and 2 retries")
	}
}

func TestUserAgentFormat(t *testing.T) {
	re := regexp.MustCompile(`^shieldlabs-go/\d+\.\d+\.\d+ \(go[^;]+; [a-z0-9]+/[a-z0-9]+\)$`)
	if ua := userAgent(); !re.MatchString(ua) {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestLargeResponseIsRejected(t *testing.T) {
	c, err := NewClient(testAPIKey, WithMaxRetries(0), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &endlessBody{}, Request: r}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "too large") {
		t.Fatalf("err = %v", err)
	}
}

type endlessBody struct{}

func (*endlessBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
func (*endlessBody) Close() error { return nil }
