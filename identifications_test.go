package shieldlabs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func ms(values ...int) []time.Duration {
	out := make([]time.Duration, len(values))
	for i, v := range values {
		out[i] = time.Duration(v) * time.Millisecond
	}
	return out
}

// step is one scripted answer of a scriptedTransport.
type step func(r *http.Request) (*http.Response, error)

// answer responds with a status, a body and optional header name and value
// pairs.
func answer(status int, body string, headerPairs ...string) step {
	return func(r *http.Request) (*http.Response, error) {
		h := http.Header{"Content-Type": {"application/json"}}
		for i := 0; i+1 < len(headerPairs); i += 2 {
			h.Set(headerPairs[i], headerPairs[i+1])
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
}

// fail fails the request with a transport error.
func fail(err error) step {
	return func(*http.Request) (*http.Response, error) { return nil, err }
}

// after moves the fake clock forward by latency before answering, like a
// slow response.
func after(clk *fakeClock, latency time.Duration, s step) step {
	return func(r *http.Request) (*http.Response, error) {
		clk.Advance(latency)
		return s(r)
	}
}

var (
	empty       = answer(200, emptyPage)
	serverError = answer(503, `{"error":"service unavailable"}`)
	rateLimited = answer(429, `{"error":"too many requests"}`)
	refused     = fail(errors.New("dial tcp 192.0.2.1:443: connect: connection refused"))
)

func found(t *testing.T) step { return answer(200, rowPage(t)) }

func retryAfter(value string) step {
	return answer(429, `{"error":"too many requests"}`, "Retry-After", value)
}

// scriptedTransport answers the n-th request with steps[n-1] (the last step
// repeats). It records when each request was sent on the fake clock, relative
// to the start, and the time left on the request's deadline, which is the
// attempt timeout minus the moment it took to send the request.
type scriptedTransport struct {
	clk   *fakeClock
	start time.Time
	steps []step

	mu       sync.Mutex
	sentAt   []time.Duration
	timeouts []time.Duration
}

func (s *scriptedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	n := len(s.sentAt)
	s.sentAt = append(s.sentAt, s.clk.Now().Sub(s.start))
	timeout := time.Duration(-1)
	if deadline, ok := r.Context().Deadline(); ok {
		timeout = time.Until(deadline)
	}
	s.timeouts = append(s.timeouts, timeout)
	s.mu.Unlock()
	return s.steps[min(n, len(s.steps)-1)](r)
}

func (s *scriptedTransport) SentAt() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.sentAt...)
}

func (s *scriptedTransport) Timeouts() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.timeouts...)
}

// newScriptedClient returns a History client whose requests are answered by
// steps and whose clock is clk.
func newScriptedClient(t *testing.T, clk *fakeClock, steps []step, opts ...Option) (*Client, *scriptedTransport) {
	t.Helper()
	st := &scriptedTransport{clk: clk, start: clk.Now(), steps: steps}
	c, _ := newTestClient(t, DefaultBaseURL, append([]Option{WithHTTPClient(&http.Client{Transport: st})}, opts...)...)
	c.t.clock = clk
	return c, st
}

func sameDurations(got, want []time.Duration) bool {
	return fmt.Sprint(got) == fmt.Sprint(want)
}

func TestGetWaitsWithBackoffSchedule(t *testing.T) {
	page := rowPage(t)
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n <= 5 {
			writeJSON(w, 200, emptyPage)
			return
		}
		writeJSON(w, 200, page)
	})
	c, clk := newTestClient(t, srv.URL)
	ident, err := c.Identifications.Get(context.Background(), testRequestID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ident == nil || ident.RequestID != testRequestID || ident.Source != SourceHistory {
		t.Fatalf("ident = %+v", ident)
	}
	if got, want := clk.Sleeps(), ms(250, 500, 1000, 1500, 2000); !sameDurations(got, want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
	if srv.Count() != 6 {
		t.Errorf("requests = %d, want 6", srv.Count())
	}
	req := srv.Request(0)
	if got := req.URL.EscapedPath(); got != "/api/v1/history/request_id/"+testRequestID {
		t.Errorf("path %s", got)
	}
	if q := req.URL.Query(); q.Get("limit") != "1" || q.Get("offset") != "0" {
		t.Errorf("query %s", req.URL.RawQuery)
	}
}

func TestGetZeroValueOptionsWait(t *testing.T) {
	for _, opts := range []*GetIdentificationOptions{nil, {}, {Timeout: 5 * time.Second}, {PollInterval: 500 * time.Millisecond}} {
		clk := newFakeClock()
		c, st := newScriptedClient(t, clk, []step{empty, found(t)})
		ident, err := c.Identifications.Get(context.Background(), testRequestID, opts)
		if err != nil || ident == nil {
			t.Fatalf("opts %+v: got %v, %v", opts, ident, err)
		}
		if len(st.SentAt()) != 2 || len(clk.Sleeps()) != 1 {
			t.Errorf("opts %+v: requests at %v, waits %v", opts, st.SentAt(), clk.Sleeps())
		}
	}
}

func TestGetNoWaitMakesOneLookup(t *testing.T) {
	clk := newFakeClock()
	c, st := newScriptedClient(t, clk, []step{empty, found(t)})
	ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{NoWait: true})
	if err != nil || ident != nil {
		t.Fatalf("got %v, %v; want nil, nil", ident, err)
	}
	// Timeout and PollInterval only apply while waiting.
	ident, err = c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{NoWait: true, Timeout: time.Minute, PollInterval: time.Second})
	if err != nil || ident == nil {
		t.Fatalf("got %v, %v", ident, err)
	}
	if len(st.SentAt()) != 2 || len(clk.Sleeps()) != 0 {
		t.Errorf("requests at %v, waits %v", st.SentAt(), clk.Sleeps())
	}
	// The single lookup uses the client's attempt timeout (10 s by default).
	for i, got := range st.Timeouts() {
		if got <= 9*time.Second || got > 10*time.Second {
			t.Errorf("lookup %d: attempt timeout %s, want 10s", i+1, got)
		}
	}
}

func TestGetNoWaitRetriesLikeHistoryRequests(t *testing.T) {
	clk := newFakeClock()
	c, _ := newScriptedClient(t, clk, []step{rateLimited, empty})
	if _, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{NoWait: true}); err != nil {
		t.Fatal(err)
	}
	// The client retries a 429 without Retry-After after at least one second.
	if got := clk.Sleeps(); !sameDurations(got, ms(1000)) {
		t.Errorf("waits = %v", got)
	}

	// A Retry-After is followed as sent: "Retry-After: 0" and a date in the
	// past retry at once, unlike inside the wait.
	for _, value := range []string{"0", "Wed, 21 Oct 2015 07:28:00 GMT"} {
		clk = newFakeClock()
		c, _ = newScriptedClient(t, clk, []step{retryAfter(value), empty})
		if _, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{NoWait: true}); err != nil {
			t.Fatal(err)
		}
		if got := clk.Sleeps(); !sameDurations(got, ms(0)) {
			t.Errorf("Retry-After %q: waits = %v", value, got)
		}
	}

	clk = newFakeClock()
	c, st := newScriptedClient(t, clk, []step{serverError})
	if _, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{NoWait: true}); !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	// Two retries with backoff (zero jitter in tests).
	if len(st.SentAt()) != 3 || !sameDurations(clk.Sleeps(), ms(250, 500)) {
		t.Errorf("requests at %v, waits %v", st.SentAt(), clk.Sleeps())
	}
}

func TestGetReturnsNilWhenTheLastLookupFindsNothing(t *testing.T) {
	clk := newFakeClock()
	c, st := newScriptedClient(t, clk, []step{empty})
	ident, err := c.Identifications.Get(context.Background(), testRequestID, nil)
	if err != nil || ident != nil {
		t.Fatalf("got %v, %v; want nil, nil", ident, err)
	}
	// The schedule, then a last wait shortened to 750 ms, so that the last
	// lookup runs at the 10-second deadline.
	if got, want := clk.Sleeps(), ms(250, 500, 1000, 1500, 2000, 2000, 2000, 750); !sameDurations(got, want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
	if got, want := st.SentAt(), ms(0, 250, 750, 1750, 3250, 5250, 7250, 9250, 10000); !sameDurations(got, want) {
		t.Errorf("lookups at %v, want %v", got, want)
	}
}

func TestGetLastLookupRunsAtTheDeadline(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		latency time.Duration
		sentAt  []time.Duration
	}{
		{"1.9 s budget", 1900 * time.Millisecond, 0, ms(0, 250, 750, 1750, 1900)},
		{"100 ms budget", 100 * time.Millisecond, 0, ms(0, 100)},
		// Each lookup takes 300 ms and every wait starts when a lookup ends.
		// The last wait is shortened to 650 ms, so that the last lookup starts
		// at the deadline.
		{"300 ms per lookup", 10 * time.Second, 300 * time.Millisecond, ms(0, 550, 1350, 2650, 4450, 6750, 9050, 10000)},
		// A lookup that ends after the deadline is the last one.
		{"5 s per lookup", 10 * time.Second, 5 * time.Second, ms(0, 5250)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, []step{after(clk, tc.latency, empty)})
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: tc.timeout})
			if err != nil || ident != nil {
				t.Fatalf("got %v, %v; want nil, nil", ident, err)
			}
			if got := st.SentAt(); !sameDurations(got, tc.sentAt) {
				t.Errorf("lookups at %v, want %v", got, tc.sentAt)
			}
		})
	}
}

func TestGetKeepsPollingThroughTransientErrors(t *testing.T) {
	clk := newFakeClock()
	c, st := newScriptedClient(t, clk, []step{
		answer(500, `{"error":"internal error"}`),
		answer(502, "<html>bad gateway</html>"),
		refused,
		fail(timeoutError{}),
		rateLimited,
		found(t),
	})
	ident, err := c.Identifications.Get(context.Background(), testRequestID, nil)
	if err != nil || ident == nil {
		t.Fatalf("got %v, %v", ident, err)
	}
	// Each failure is followed by the next lookup on the schedule, and each
	// lookup is a single HTTP attempt: no retries in between.
	if got, want := clk.Sleeps(), ms(250, 500, 1000, 1500, 2000); !sameDurations(got, want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
	if got, want := st.SentAt(), ms(0, 250, 750, 1750, 3250, 5250); !sameDurations(got, want) {
		t.Errorf("lookups at %v, want %v", got, want)
	}
}

func TestGetEachLookupIsOneAttempt(t *testing.T) {
	// The client's retries do not apply inside the wait, however many are
	// configured.
	clk := newFakeClock()
	c, st := newScriptedClient(t, clk, []step{serverError}, WithMaxRetries(5))
	if _, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: time.Second}); !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if got, want := st.SentAt(), ms(0, 250, 750, 1000); !sameDurations(got, want) {
		t.Errorf("lookups at %v, want %v", got, want)
	}
	if got, want := clk.Sleeps(), ms(250, 500, 250); !sameDurations(got, want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
}

func TestGetReturnsTheLastErrorAtTheDeadline(t *testing.T) {
	tests := []struct {
		name    string
		steps   []step
		timeout time.Duration
		want    error // nil for (nil, nil)
		status  int   // status of the returned *APIError, 0 for none
		sentAt  []time.Duration
	}{
		{"server errors", []step{serverError}, 3 * time.Second, ErrServer, 503, ms(0, 250, 750, 1750, 3000)},
		{"connection failures", []step{refused}, 2 * time.Second, ErrConnection, 0, ms(0, 250, 750, 1750, 2000)},
		{"attempt timeouts", []step{fail(timeoutError{})}, 2 * time.Second, ErrTimeout, 0, ms(0, 250, 750, 1750, 2000)},
		// Every 429 asks for at least one second; the last lookup runs at the
		// deadline.
		{"rate limits", []step{rateLimited}, 3 * time.Second, ErrRateLimited, 429, ms(0, 1000, 2000, 3000)},
		// Only the last lookup counts: a failure after empty answers is
		// returned,
		{"empty answers, then an error", []step{empty, empty, empty, answer(502, "")}, time.Second, ErrServer, 502, ms(0, 250, 750, 1000)},
		// the failure of the last lookup and not of an earlier one,
		{"two different errors", []step{answer(500, ""), answer(502, "")}, 250 * time.Millisecond, ErrServer, 502, ms(0, 250)},
		// and an empty answer after failures means "not found in time".
		{"errors, then an empty answer", []step{serverError, refused, fail(timeoutError{}), empty}, time.Second, nil, 0, ms(0, 250, 750, 1000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, tc.steps)
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: tc.timeout})
			if ident != nil {
				t.Fatalf("ident = %+v, want nil", ident)
			}
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var apiErr *APIError
			if tc.status != 0 && (!errors.As(err, &apiErr) || apiErr.StatusCode != tc.status) {
				t.Errorf("err = %v, want HTTP %d", err, tc.status)
			}
			if got := st.SentAt(); !sameDurations(got, tc.sentAt) {
				t.Errorf("lookups at %v, want %v", got, tc.sentAt)
			}
		})
	}
}

func TestPollAttemptTimeout(t *testing.T) {
	const s = time.Second
	tests := []struct{ client, remaining, want time.Duration }{
		{10 * s, 10 * s, 10 * s},
		{10 * s, 5 * s, 5 * s},
		{10 * s, 300 * time.Millisecond, s}, // at least one second
		{10 * s, 0, s},                      // the lookup at the deadline
		{10 * s, -2 * s, s},
		{2 * s, 5 * s, 2 * s}, // never more than the client timeout
		{500 * time.Millisecond, 0, 500 * time.Millisecond},
		{0, 5 * s, 5 * s}, // no client timeout
		{0, 0, s},
	}
	for _, tc := range tests {
		if got := pollAttemptTimeout(tc.client, tc.remaining); got != tc.want {
			t.Errorf("client timeout %s, %s left: got %s, want %s", tc.client, tc.remaining, got, tc.want)
		}
	}
}

func TestGetLookupAttemptTimeouts(t *testing.T) {
	// Lookups at 0, 0.25, 0.75, 1.75, 3.25 and 5 s of a 5-second wait. Each
	// gets min(client timeout, max(time left, 1 s)).
	tests := []struct {
		name string
		opts []Option
		want []time.Duration
	}{
		{"default client timeout", nil, ms(5000, 4750, 4250, 3250, 1750, 1000)},
		{"client timeout 2 s", []Option{WithTimeout(2 * time.Second)}, ms(2000, 2000, 2000, 2000, 1750, 1000)},
		{"client timeout 500 ms", []Option{WithTimeout(500 * time.Millisecond)}, ms(500, 500, 500, 500, 500, 500)},
		{"no client timeout", []Option{WithTimeout(0)}, ms(5000, 4750, 4250, 3250, 1750, 1000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, []step{empty}, tc.opts...)
			if _, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: 5 * time.Second}); err != nil {
				t.Fatal(err)
			}
			got := st.Timeouts()
			if len(got) != len(tc.want) {
				t.Fatalf("attempt timeouts %v, want %v", got, tc.want)
			}
			for i := range got {
				// Recorded when the request was sent, a moment after the
				// timeout started.
				if got[i] > tc.want[i] || got[i] < tc.want[i]-100*time.Millisecond {
					t.Errorf("lookup %d: attempt timeout %s, want %s", i+1, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestGetLastLookupGetsAtLeastOneSecond(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	c, err := NewClient(testAPIKey, WithBaseURL(srv.URL), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: 100 * time.Millisecond})
	elapsed := time.Since(start)
	if ident != nil || !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, %v", ident, err)
	}
	// The lookup had one second to answer although the budget was 100 ms.
	// After it the time was up, so it was the only one.
	if elapsed < time.Second || elapsed > 3*time.Second {
		t.Errorf("took %s, want about one second", elapsed)
	}
	if srv.Count() != 1 {
		t.Errorf("requests = %d, want 1", srv.Count())
	}
}

func TestGetWithTheRealClock(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	c, err := NewClient(testAPIKey, WithBaseURL(srv.URL), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: 450 * time.Millisecond})
	elapsed := time.Since(start)
	if err != nil || ident != nil {
		t.Fatalf("got %v, %v; want nil, nil", ident, err)
	}
	// Lookups at 0 and 0.25 s, and the last one at the 0.45 s deadline.
	if srv.Count() != 3 {
		t.Errorf("requests = %d, want 3", srv.Count())
	}
	if elapsed < 450*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("took %s, want about 450ms", elapsed)
	}
}

func TestGetRateLimitWaitsAtLeastOneSecond(t *testing.T) {
	const pastDate = "Wed, 21 Oct 2015 07:28:00 GMT"
	tests := []struct {
		name    string
		steps   []step
		timeout time.Duration
		sentAt  []time.Duration
	}{
		// The first scheduled wait is 250 ms; after a 429 it is one second.
		{"no Retry-After", []step{rateLimited, found(t)}, 0, ms(0, 1000)},
		// A shorter Retry-After delay is raised to one second.
		{"short Retry-After", []step{retryAfter("0.2"), found(t)}, 0, ms(0, 1000)},
		// "Retry-After: 0", a date in the past and values that are not a delay
		// count as 0, and the one-second minimum still applies.
		{"zero Retry-After", []step{retryAfter("0"), found(t)}, 0, ms(0, 1000)},
		{"Retry-After date in the past", []step{retryAfter(pastDate), found(t)}, 0, ms(0, 1000)},
		{"negative Retry-After", []step{retryAfter("-3"), found(t)}, 0, ms(0, 1000)},
		{"invalid Retry-After", []step{retryAfter("soon"), found(t)}, 0, ms(0, 1000)},
		// A scheduled wait longer than one second is kept.
		{"later lookup", []step{empty, empty, empty, empty, rateLimited, found(t)}, 0, ms(0, 250, 750, 1750, 3250, 5250)},
		{"later lookup, short Retry-After", []step{empty, empty, empty, retryAfter("0.5"), found(t)}, 0, ms(0, 250, 750, 1750, 3250)},
		// The schedule goes on after the longer wait: 500 ms, 1 s, 1.5 s, 2 s.
		{"schedule after a 429", []step{rateLimited, empty, empty, empty, empty, found(t)}, 0, ms(0, 1000, 1500, 2500, 4000, 6000)},
		// Near the deadline the wait is shortened like any other, so that the
		// last lookup still runs at the deadline.
		{"near the deadline", []step{empty, empty, rateLimited, found(t)}, time.Second, ms(0, 250, 750, 1000)},
		{"zero Retry-After near the deadline", []step{empty, empty, retryAfter("0"), found(t)}, time.Second, ms(0, 250, 750, 1000)},
		{"past date near the deadline", []step{empty, empty, retryAfter(pastDate), found(t)}, time.Second, ms(0, 250, 750, 1000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, tc.steps)
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: tc.timeout})
			if err != nil || ident == nil {
				t.Fatalf("got %v, %v", ident, err)
			}
			if got := st.SentAt(); !sameDurations(got, tc.sentAt) {
				t.Errorf("lookups at %v, want %v", got, tc.sentAt)
			}
		})
	}
}

func TestGetRetryAfter(t *testing.T) {
	// An HTTP date one minute ahead asks for about 60 seconds, capped at 10.
	inAMinute := time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)
	tests := []struct {
		name    string
		steps   []step
		timeout time.Duration
		found   bool
		waits   []time.Duration
	}{
		// Retry-After replaces a shorter scheduled wait.
		{"within the time left", []step{retryAfter("3"), found(t)}, 10 * time.Second, true, ms(3000)},
		// A longer scheduled wait is kept.
		{"shorter than the scheduled wait", []step{empty, empty, empty, empty, retryAfter("1.5"), found(t)}, 10 * time.Second, true, ms(250, 500, 1000, 1500, 2000)},
		// Longer delays are capped at 10 seconds.
		{"capped at 10 s", []step{retryAfter("30"), found(t)}, 20 * time.Second, true, ms(10000)},
		{"very long delay capped at 10 s", []step{retryAfter("99999999"), found(t)}, 20 * time.Second, true, ms(10000)},
		{"HTTP date capped at 10 s", []step{retryAfter(inAMinute), found(t)}, 20 * time.Second, true, ms(10000)},
		// A delay that ends exactly at the deadline leaves the last lookup.
		{"ending at the deadline", []step{retryAfter("2"), found(t)}, 2 * time.Second, true, ms(2000)},
		// Only the delay itself must fit: the longer wait (the 1.5 s step) is
		// shortened to the deadline.
		{"short delay near the deadline", []step{empty, empty, empty, retryAfter("0.2"), found(t)}, 2 * time.Second, true, ms(250, 500, 1000, 250)},
		// A delay that ends after the deadline returns the 429 at once.
		{"longer than the time left", []step{retryAfter("5"), found(t)}, 3 * time.Second, false, nil},
		{"capped delay longer than the time left", []step{retryAfter("30"), found(t)}, 5 * time.Second, false, nil},
		{"very long delay longer than the time left", []step{retryAfter("99999999"), found(t)}, 5 * time.Second, false, nil},
		{"HTTP date after the deadline", []step{retryAfter(inAMinute), found(t)}, 5 * time.Second, false, nil},
		{"longer than the time left after a few lookups", []step{empty, empty, retryAfter("2"), found(t)}, 2 * time.Second, false, ms(250, 500)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, tc.steps)
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: tc.timeout})
			if tc.found && (err != nil || ident == nil) {
				t.Fatalf("got %v, %v", ident, err)
			}
			var apiErr *APIError
			if !tc.found && (ident != nil || !errors.As(err, &apiErr) || apiErr.StatusCode != 429 || apiErr.RetryAfter == 0) {
				t.Fatalf("got %v, %v; want the 429 error", ident, err)
			}
			if got := clk.Sleeps(); !sameDurations(got, tc.waits) {
				t.Errorf("waits = %v, want %v", got, tc.waits)
			}
			if got := len(st.SentAt()); got != len(tc.waits)+1 {
				t.Errorf("requests = %d, want %d", got, len(tc.waits)+1)
			}
		})
	}
}

func TestGetStopsAtOnce(t *testing.T) {
	tests := []struct {
		name   string
		steps  []step
		want   error
		status int
		waits  []time.Duration
	}{
		{"400", []step{answer(400, `{"error":"bad request"}`)}, ErrBadRequest, 400, nil},
		{"401", []step{answer(401, `{"error":"invalid api key"}`)}, ErrAuthentication, 401, nil},
		{"403", []step{answer(403, `{"error":"forbidden"}`)}, ErrAuthentication, 403, nil},
		{"404", []step{answer(404, "404 page not found")}, ErrNotFound, 404, nil},
		{"401 after empty answers", []step{empty, empty, answer(401, `{"error":"invalid api key"}`)}, ErrAuthentication, 401, ms(250, 500)},
		// Another lookup cannot change an unreadable page either.
		{"unreadable page", []step{answer(200, "<html>maintenance</html>")}, nil, 200, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			steps := append(append([]step(nil), tc.steps...), found(t))
			c, st := newScriptedClient(t, clk, steps)
			ident, err := c.Identifications.Get(context.Background(), testRequestID, nil)
			if ident != nil || err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, %v", ident, err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
				t.Errorf("err = %v, want HTTP %d", err, tc.status)
			}
			if got := clk.Sleeps(); !sameDurations(got, tc.waits) {
				t.Errorf("waits = %v, want %v", got, tc.waits)
			}
			if got := len(st.SentAt()); got != len(tc.waits)+1 {
				t.Errorf("requests = %d, want %d", got, len(tc.waits)+1)
			}
		})
	}
}

func TestGetCustomPollInterval(t *testing.T) {
	tests := []struct {
		interval time.Duration
		want     []time.Duration
	}{
		// The waits are p, 2p, 4p, 6p and then 8p, each capped at max(2 s, p).
		{100 * time.Millisecond, ms(100, 200, 400, 600, 800, 800, 800)},
		{400 * time.Millisecond, ms(400, 800, 1600, 2000, 2000)},
		{600 * time.Millisecond, ms(600, 1200, 2000, 2000, 2000)},
		{time.Second, ms(1000, 2000, 2000)},
		// Intervals below 100 ms are raised to 100 ms, including 250, which is
		// 250 ns and not 250 ms.
		{10 * time.Millisecond, ms(100, 200, 400, 600, 800, 800)},
		{250, ms(100, 200, 400, 600, 800)},
		// An interval above 2 s is used for every wait.
		{3 * time.Second, ms(3000, 3000)},
	}
	for _, tc := range tests {
		page := rowPage(t)
		want := tc.want
		srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
			if n <= len(want) {
				writeJSON(w, 200, emptyPage)
				return
			}
			writeJSON(w, 200, page)
		})
		c, clk := newTestClient(t, srv.URL)
		ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{Timeout: time.Minute, PollInterval: tc.interval})
		if err != nil || ident == nil {
			t.Fatalf("interval %s: got %v, %v", tc.interval, ident, err)
		}
		if got := clk.Sleeps(); !sameDurations(got, want) {
			t.Errorf("interval %s: waits = %v, want %v", tc.interval, got, want)
		}
	}
}

func TestGetFollowsTheLadderOfItsPollInterval(t *testing.T) {
	// The waits are p, 2p, 4p, 6p and then 8p, each capped at max(2 s, p).
	// The last wait is shortened so that the last lookup runs at the 10-second
	// deadline.
	tests := []struct {
		interval time.Duration
		waits    []time.Duration
		sentAt   []time.Duration
	}{
		{250 * time.Millisecond, ms(250, 500, 1000, 1500, 2000, 2000, 2000, 750), ms(0, 250, 750, 1750, 3250, 5250, 7250, 9250, 10000)},
		{time.Second, ms(1000, 2000, 2000, 2000, 2000, 1000), ms(0, 1000, 3000, 5000, 7000, 9000, 10000)},
		{3 * time.Second, ms(3000, 3000, 3000, 1000), ms(0, 3000, 6000, 9000, 10000)},
	}
	for _, tc := range tests {
		t.Run(tc.interval.String(), func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, []step{empty})
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{PollInterval: tc.interval})
			if err != nil || ident != nil {
				t.Fatalf("got %v, %v; want nil, nil", ident, err)
			}
			if got := clk.Sleeps(); !sameDurations(got, tc.waits) {
				t.Errorf("waits = %v, want %v", got, tc.waits)
			}
			if got := st.SentAt(); !sameDurations(got, tc.sentAt) {
				t.Errorf("lookups at %v, want %v", got, tc.sentAt)
			}
		})
	}
}

func TestGetRateLimitKeepsTheLadderOfALongPollInterval(t *testing.T) {
	// The 3 s step is longer than the one-second floor and than a shorter
	// Retry-After delay. A longer delay wins, and the ladder then goes on
	// with its next step.
	tests := []struct {
		name  string
		first step
		waits []time.Duration
	}{
		{"no Retry-After", rateLimited, ms(3000, 3000)},
		{"shorter Retry-After", retryAfter("2"), ms(3000, 3000)},
		{"longer Retry-After", retryAfter("5"), ms(5000, 3000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			c, st := newScriptedClient(t, clk, []step{tc.first, empty, found(t)})
			ident, err := c.Identifications.Get(context.Background(), testRequestID, &GetIdentificationOptions{PollInterval: 3 * time.Second})
			if err != nil || ident == nil {
				t.Fatalf("got %v, %v", ident, err)
			}
			if got := clk.Sleeps(); !sameDurations(got, tc.waits) {
				t.Errorf("waits = %v, want %v", got, tc.waits)
			}
			if got := len(st.SentAt()); got != 3 {
				t.Errorf("requests = %d, want 3", got)
			}
		})
	}
}

func TestGetValidation(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	c, _ := newTestClient(t, srv.URL)
	for _, id := range []string{"", "abc", "not-a-uuid", testRequestID + "x"} {
		if _, err := c.Identifications.Get(context.Background(), id, nil); !errors.Is(err, ErrValidation) {
			t.Errorf("request ID %q: err = %v", id, err)
		}
	}
	for _, opts := range []*GetIdentificationOptions{{Timeout: -1}, {PollInterval: -time.Second}, {NoWait: true, Timeout: -1}} {
		if _, err := c.Identifications.Get(context.Background(), testRequestID, opts); !errors.Is(err, ErrValidation) {
			t.Errorf("opts %+v: err = %v", opts, err)
		}
	}
	if srv.Count() != 0 {
		t.Errorf("validation errors must not send requests, sent %d", srv.Count())
	}
	// Upper-case request IDs are accepted and sent lowercase.
	if _, err := c.Identifications.Get(context.Background(), "02F1D973-84DB-4156-A7F7-E799E6BF389B", &GetIdentificationOptions{NoWait: true}); err != nil {
		t.Fatal(err)
	}
	if got := srv.Request(0).URL.EscapedPath(); got != "/api/v1/history/request_id/"+testRequestID {
		t.Errorf("path %s", got)
	}
}

func TestGetHonoursContextCancellation(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	c, _ := newTestClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Identifications.Get(ctx, testRequestID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}

	// Cancelled during a wait.
	ctx2, cancel2 := context.WithCancel(context.Background())
	c.t.clock = &cancellingClock{fakeClock: newFakeClock(), cancel: cancel2}
	_, err = c.Identifications.Get(ctx2, testRequestID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}

	// A context deadline ends the wait even while the budget lasts.
	expired, cancel3 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel3()
	_, err = c.Identifications.Get(expired, testRequestID, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// cancellingClock cancels the caller's context on the first sleep.
type cancellingClock struct {
	*fakeClock
	cancel context.CancelFunc
}

func (c *cancellingClock) Sleep(ctx context.Context, d time.Duration) error {
	c.cancel()
	return ctx.Err()
}

func TestPollSchedule(t *testing.T) {
	// every repeats one wait eight times.
	every := func(d time.Duration) []time.Duration {
		return []time.Duration{d, d, d, d, d, d, d, d}
	}
	tests := []struct {
		interval time.Duration
		want     []time.Duration
	}{
		{defaultPollInterval, ms(250, 500, 1000, 1500, 2000, 2000, 2000, 2000)},
		{100 * time.Millisecond, ms(100, 200, 400, 600, 800, 800, 800, 800)},
		{200 * time.Millisecond, ms(200, 400, 800, 1200, 1600, 1600, 1600, 1600)},
		{300 * time.Millisecond, ms(300, 600, 1200, 1800, 2000, 2000, 2000, 2000)},
		{500 * time.Millisecond, ms(500, 1000, 2000, 2000, 2000, 2000, 2000, 2000)},
		{time.Second, ms(1000, 2000, 2000, 2000, 2000, 2000, 2000, 2000)},
		{1999 * time.Millisecond, ms(1999, 2000, 2000, 2000, 2000, 2000, 2000, 2000)},
		// An interval of 2 s or more is the cap, so it is every wait.
		{2 * time.Second, every(2 * time.Second)},
		{3 * time.Second, every(3 * time.Second)},
		{time.Minute, every(time.Minute)},
		// The multiples of a huge interval do not overflow.
		{time.Duration(math.MaxInt64), every(time.Duration(math.MaxInt64))},
	}
	for _, tc := range tests {
		s := newPollSchedule(tc.interval)
		var got []time.Duration
		for range tc.want {
			got = append(got, s.next())
		}
		if !sameDurations(got, tc.want) {
			t.Errorf("interval %s: schedule = %v, want %v", tc.interval, got, tc.want)
		}
	}
}
