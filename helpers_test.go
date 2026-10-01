package shieldlabs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAPIKey    = "sec_abcd1234-efgh5678-ijkl9012"
	testSecretKey = "0123456789abcdef0123456789abcdef"
	testRequestID = "a5b7c9d1-e3f5-4a7b-9c1d-3e5f7a9b1c3d"
)

// readFixture returns a file from testdata/.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fakeClock records sleeps and advances a virtual time instead of waiting.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

// Advance moves the virtual time forward without recording a sleep, for
// example to simulate the latency of a request.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

// discardLogger keeps configuration warnings out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestClient returns a History client pointed at baseURL with a fake clock
// and deterministic jitter (backoff delays at half their maximum).
func newTestClient(t *testing.T, baseURL string, opts ...Option) (*Client, *fakeClock) {
	t.Helper()
	opts = append([]Option{WithBaseURL(baseURL), WithLogger(discardLogger())}, opts...)
	c, err := NewClient(testAPIKey, opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	clk := newFakeClock()
	c.t.clock = clk
	c.t.jitter = func() float64 { return 0 }
	return c, clk
}

func newTestManagementClient(t *testing.T, baseURL string, opts ...Option) (*ManagementClient, *fakeClock) {
	t.Helper()
	opts = append([]Option{WithBaseURL(baseURL)}, opts...)
	m, err := NewManagementClient(testSecretKey, "example.com", opts...)
	if err != nil {
		t.Fatalf("NewManagementClient: %v", err)
	}
	clk := newFakeClock()
	m.t.clock = clk
	m.t.jitter = func() float64 { return 0 }
	return m, clk
}

// recordingServer serves canned responses and records the requests it saw.
type recordingServer struct {
	*httptest.Server
	count    atomic.Int32
	mu       sync.Mutex
	requests []*http.Request
}

func newRecordingServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(rs.count.Add(1))
		rs.mu.Lock()
		rs.requests = append(rs.requests, snapshotRequest(r))
		rs.mu.Unlock()
		handler(w, r, n)
	}))
	t.Cleanup(rs.Close)
	return rs
}

// snapshotRequest keeps what the tests inspect after the handler returned.
func snapshotRequest(r *http.Request) *http.Request {
	u := *r.URL
	header := http.Header{}
	for key, values := range r.Header {
		header[key] = append([]string(nil), values...)
	}
	return &http.Request{Method: r.Method, URL: &u, Header: header}
}

func (rs *recordingServer) Count() int { return int(rs.count.Load()) }

func (rs *recordingServer) Request(i int) *http.Request {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.requests[i]
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// emptyPage and rowPage build History bodies.
const emptyPage = `{"data":[],"total":0}`

func rowPage(t *testing.T) string {
	t.Helper()
	var page struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(readFixture(t, "history-page.json"), &page); err != nil {
		t.Fatal(err)
	}
	return `{"data":[` + string(page.Data[0]) + `],"total":1}`
}

// normalizationCase is one entry of normalization-cases.json.
type normalizationCase struct {
	Name     string          `json:"name"`
	Source   string          `json:"source"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
}

func normalizationCases(t *testing.T) []normalizationCase {
	t.Helper()
	var f struct {
		Cases []normalizationCase `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "normalization-cases.json"), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no normalization cases")
	}
	return f.Cases
}

// expectedByRequestID returns the expected Identification objects of one
// source, keyed by request ID.
func expectedByRequestID(t *testing.T, source string) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for _, c := range normalizationCases(t) {
		if c.Source != source {
			continue
		}
		var probe struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(c.Expected, &probe); err != nil {
			t.Fatal(err)
		}
		out[probe.RequestID] = c.Expected
	}
	return out
}

// fixtureView renders an Identification in the fixture shape: the JSON
// encoding of the model with observed_at truncated to milliseconds.
func fixtureView(t *testing.T, ident *Identification) map[string]any {
	t.Helper()
	b, err := json.Marshal(ident)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if ident.ObservedAt.IsZero() {
		m["observed_at"] = nil
	} else {
		m["observed_at"] = ident.ObservedAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	}
	return m
}

// assertMatchesFixture compares an Identification with an expected fixture
// object and reports every differing key.
func assertMatchesFixture(t *testing.T, name string, ident *Identification, expected json.RawMessage) {
	t.Helper()
	var want map[string]any
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	got := fixtureView(t, ident)
	if reflect.DeepEqual(got, want) {
		return
	}
	keys := map[string]bool{}
	for k := range got {
		keys[k] = true
	}
	for k := range want {
		keys[k] = true
	}
	var diffs []string
	for k := range keys {
		if !reflect.DeepEqual(got[k], want[k]) {
			diffs = append(diffs, fmt.Sprintf("  %s:\n    got  %s\n    want %s", k, mustJSON(got[k]), mustJSON(want[k])))
		}
	}
	sort.Strings(diffs)
	t.Errorf("%s: normalized identification differs:\n%s", name, strings.Join(diffs, "\n"))
}

func mustJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSpace(buf.String())
}
