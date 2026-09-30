package shieldlabs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestHistorySearchFixturePage(t *testing.T) {
	body := readFixture(t, "history-page.json")
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	c, _ := newTestClient(t, srv.URL)

	page, err := c.History.Search(context.Background(), LookupDeviceID, "AC7C303D-971B-41D1-8E25-CD5B46B46AED", &HistorySearchOptions{Limit: 50, Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 37 || len(page.Data) != 5 {
		t.Fatalf("page: total %d, %d rows", page.Total, len(page.Data))
	}
	expected := expectedByRequestID(t, "history")
	for _, ident := range page.Data {
		want, ok := expected[ident.RequestID]
		if !ok {
			t.Fatalf("no expected identification for %s", ident.RequestID)
		}
		assertMatchesFixture(t, ident.RequestID, ident, want)
	}

	req := srv.Request(0)
	if req.Method != http.MethodGet {
		t.Errorf("method %s", req.Method)
	}
	if got := req.URL.EscapedPath(); got != "/api/v1/history/device_id/ac7c303d-971b-41d1-8e25-cd5b46b46aed" {
		t.Errorf("path %s (UUIDs are sent lowercase)", got)
	}
	if got := req.URL.Query().Get("limit"); got != "50" {
		t.Errorf("limit %s", got)
	}
	if got := req.URL.Query().Get("offset"); got != "100" {
		t.Errorf("offset %s", got)
	}
	assertStandardHeaders(t, req, "Bearer "+testAPIKey)
}

func assertStandardHeaders(t *testing.T, req *http.Request, auth string) {
	t.Helper()
	if got := req.Header.Get("Authorization"); got != auth {
		t.Errorf("Authorization = %q, want %q", got, auth)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	ua := req.Header.Get("User-Agent")
	if !strings.HasPrefix(ua, "shieldlabs-go/"+Version+" (go") || !strings.Contains(ua, "/") {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestHistorySearchEmptyPageAndDefaults(t *testing.T) {
	body := readFixture(t, "history-empty.json")
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	c, _ := newTestClient(t, srv.URL)
	page, err := c.History.Search(context.Background(), LookupIP, "192.0.2.44", nil)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 || page.Data == nil || len(page.Data) != 0 {
		t.Fatalf("page = %+v", page)
	}
	// Limit 0 selects the default of 20; the offset defaults to 0.
	page, err = c.History.Search(context.Background(), LookupIP, "192.0.2.44", &HistorySearchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		q := srv.Request(i).URL.Query()
		if q.Get("limit") != "20" || q.Get("offset") != "0" {
			t.Errorf("request %d query = %s", i, srv.Request(i).URL.RawQuery)
		}
		if got := srv.Request(i).URL.EscapedPath(); got != "/api/v1/history/ip/192.0.2.44" {
			t.Errorf("path %s", got)
		}
	}
	_ = page
}

func TestHistorySearchUserHIDEncoding(t *testing.T) {
	var (
		mu     sync.Mutex
		values []string
	)
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		// The decoded path is what a Go server matches against.
		mu.Lock()
		values = append(values, strings.TrimPrefix(r.URL.Path, "/api/v1/history/user_hid/"))
		mu.Unlock()
		writeJSON(w, 200, emptyPage)
	})
	c, _ := newTestClient(t, srv.URL)
	tests := []struct{ value, path string }{
		{"b c?d%é#", "/api/v1/history/user_hid/b%20c%3Fd%25%C3%A9%23"},
		{"anonymous", "/api/v1/history/user_hid/anonymous"},
		{"Mixed+Case", "/api/v1/history/user_hid/Mixed+Case"},
		{" ", "/api/v1/history/user_hid/%20"},
		{"a,b", "/api/v1/history/user_hid/a,b"},
		{"a;b", "/api/v1/history/user_hid/a;b"},
		{"x$y&z", "/api/v1/history/user_hid/x$y&z"},
		{"a@b", "/api/v1/history/user_hid/a@b"},
		{"a:b=c", "/api/v1/history/user_hid/a:b=c"},
		{"a!b c", "/api/v1/history/user_hid/a%21b%20c"},
		{"!'()*", "/api/v1/history/user_hid/%21%27%28%29%2A"},
		{"*", "/api/v1/history/user_hid/%2A"},
		{"a%2Fb", "/api/v1/history/user_hid/a%252Fb"},
		{"-._~", "/api/v1/history/user_hid/-._~"},
		{"...", "/api/v1/history/user_hid/..."},
		{"ü", "/api/v1/history/user_hid/%C3%BC"},
	}
	for i, tc := range tests {
		if _, err := c.History.Search(context.Background(), LookupUserHID, tc.value, nil); err != nil {
			t.Fatalf("user_hid %q: %v", tc.value, err)
		}
		if got := srv.Request(i).URL.EscapedPath(); got != tc.path {
			t.Errorf("user_hid %q: path %s, want %s", tc.value, got, tc.path)
		}
		mu.Lock()
		got := values[i]
		mu.Unlock()
		if got != tc.value {
			t.Errorf("user_hid %q: the server decoded %q", tc.value, got)
		}
	}
}

// TestEscapePathValueIsCanonical checks the property the History API relies
// on: the escaped path is the one a Go server considers canonical (no raw
// path is kept), so the server decodes the value instead of comparing the
// escaped text.
func TestEscapePathValueIsCanonical(t *testing.T) {
	const prefix = "/api/v1/history/user_hid/"
	values := []string{"", "*", "a b", "ü", "日本", "%", "%2F", "a%2Cb", "\x00\x7f\xff", "?#[]{}|\\^`\"<>", "$&+,:;=@"}
	for c := 0; c < 256; c++ {
		if c != '/' {
			values = append(values, "a"+string([]byte{byte(c)})+"b")
		}
	}
	for _, v := range values {
		// Byte for byte what Go's own path escaping produces.
		if got, want := prefix+escapePathValue(v), (&url.URL{Path: prefix + v}).EscapedPath(); got != want {
			t.Errorf("%q: escaped as %q, Go escapes it as %q", v, got, want)
		}
		u, err := url.ParseRequestURI(prefix + escapePathValue(v))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if u.Path != prefix+v {
			t.Errorf("%q: decoded path %q", v, u.Path)
		}
		if u.RawPath != "" {
			t.Errorf("%q: escaping %q is not canonical", v, u.RawPath)
		}
	}
}

func TestHistorySearchValidation(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	c, _ := newTestClient(t, srv.URL)
	uuid := "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"
	tests := []struct {
		name   string
		lookup LookupType
		value  string
		opts   *HistorySearchOptions
	}{
		{"unknown type", "email", "someone@example.com", nil},
		{"auto type", "auto", uuid, nil},
		{"empty type", "", uuid, nil},
		{"bad uuid", LookupDeviceID, "abc", nil},
		{"uuid with braces", LookupVisitorID, "{" + uuid + "}", nil},
		{"uuid without dashes", LookupRequestID, strings.ReplaceAll(uuid, "-", ""), nil},
		{"uuid with spaces", LookupSessionID, " " + uuid, nil},
		{"empty cookie id", LookupCookieID, "", nil},
		{"ipv6", LookupIP, "2001:db8::1", nil},
		{"ipv4 mapped ipv6", LookupIP, "::ffff:192.0.2.1", nil},
		{"bad ipv4", LookupIP, "192.0.2.300", nil},
		{"ipv4 with port", LookupIP, "192.0.2.1:80", nil},
		{"empty user_hid", LookupUserHID, "", nil},
		{"user_hid with a slash", LookupUserHID, "a/b", nil},
		{"user_hid that is a slash", LookupUserHID, "/", nil},
		{"user_hid with an escaped slash and a slash", LookupUserHID, "a%2F/b", nil},
		{"user_hid dot", LookupUserHID, ".", nil},
		{"user_hid dot dot", LookupUserHID, "..", nil},
		{"user_hid invalid UTF-8", LookupUserHID, "a\xffb", nil},
		{"limit negative", LookupDeviceID, uuid, &HistorySearchOptions{Limit: -1}},
		{"limit 101", LookupDeviceID, uuid, &HistorySearchOptions{Limit: 101}},
		{"offset negative", LookupDeviceID, uuid, &HistorySearchOptions{Limit: 10, Offset: -1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.History.Search(context.Background(), tc.lookup, tc.value, tc.opts)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
	if srv.Count() != 0 {
		t.Fatalf("validation errors must not send requests, sent %d", srv.Count())
	}
	// The boundaries are accepted.
	for _, limit := range []int{1, 100} {
		if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, &HistorySearchOptions{Limit: limit}); err != nil {
			t.Errorf("limit %d: %v", limit, err)
		}
	}
}

// pagedServer serves History pages from a list of rows that can change
// between requests.
type pagedServer struct {
	mu         sync.Mutex
	rows       []string
	total      int
	overrides  map[int]func(w http.ResponseWriter) // by request number
	afterFirst func(p *pagedServer)
	offsets    []int
}

func (p *pagedServer) handler(w http.ResponseWriter, r *http.Request, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f, ok := p.overrides[n]; ok {
		f(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	p.offsets = append(p.offsets, offset)
	var page []string
	for i := offset; i < len(p.rows) && i < offset+limit; i++ {
		page = append(page, p.rows[i])
	}
	total := p.total
	if total == 0 {
		total = len(p.rows)
	}
	writeJSON(w, 200, fmt.Sprintf(`{"data":[%s],"total":%d}`, strings.Join(page, ","), total))
	if n == 1 && p.afterFirst != nil {
		p.afterFirst(p)
	}
}

func row(requestID string, extra ...string) string {
	fields := append([]string{fmt.Sprintf(`"request_id":%q`, requestID), `"created_at":"2026-09-30 12:00:00.000"`}, extra...)
	return "{" + strings.Join(fields, ",") + "}"
}

func uuidN(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func collect(t *testing.T, c *Client, opts *HistoryIterateOptions) ([]string, error) {
	t.Helper()
	var ids []string
	for ident, err := range c.History.All(context.Background(), LookupDeviceID, uuidN(99), opts) {
		if err != nil {
			return ids, err
		}
		ids = append(ids, ident.RequestID)
	}
	return ids, nil
}

func TestHistoryAllPagesUntilTotal(t *testing.T) {
	p := &pagedServer{rows: []string{row(uuidN(1)), row(uuidN(2)), row(uuidN(3)), row(uuidN(4)), row(uuidN(5))}}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	ids, err := collect(t, c, &HistoryIterateOptions{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != strings.Join([]string{uuidN(1), uuidN(2), uuidN(3), uuidN(4), uuidN(5)}, ",") {
		t.Errorf("ids = %v", ids)
	}
	if srv.Count() != 3 || fmt.Sprint(p.offsets) != "[0 2 4]" {
		t.Errorf("requests = %d, offsets = %v", srv.Count(), p.offsets)
	}
	if got := srv.Request(0).URL.Query().Get("limit"); got != "2" {
		t.Errorf("page size sent as limit = %s", got)
	}
}

func TestHistoryAllDefaultPageSize(t *testing.T) {
	p := &pagedServer{rows: []string{row(uuidN(1))}}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	if _, err := collect(t, c, nil); err != nil {
		t.Fatal(err)
	}
	if got := srv.Request(0).URL.Query().Get("limit"); got != "100" {
		t.Errorf("default page size = %s", got)
	}
}

func TestHistoryAllDeduplicatesShiftedRows(t *testing.T) {
	// A new identification arrives after the first page, so offset paging
	// returns row 2 again on the second page.
	p := &pagedServer{
		rows: []string{row(uuidN(1)), row(uuidN(2)), row(uuidN(3)), row(uuidN(4))},
		afterFirst: func(p *pagedServer) {
			p.rows = append([]string{row(uuidN(9))}, p.rows...)
		},
	}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	ids, err := collect(t, c, &HistoryIterateOptions{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{uuidN(1), uuidN(2), uuidN(3), uuidN(4)}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	if srv.Count() != 3 {
		t.Errorf("requests = %d", srv.Count())
	}
}

func TestHistoryAllKeepsDistinctRowsWithoutRequestID(t *testing.T) {
	p := &pagedServer{rows: []string{
		row(NilUUID, `"ver":1`, `"score":999`),
		row(NilUUID, `"ver":2`, `"score":999`),
		row(NilUUID, `"ver":2`, `"score":999`), // same row repeated
		row(""),
	}}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	ids, err := collect(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Errorf("want 3 distinct rows, got %d: %v", len(ids), ids)
	}
}

func TestHistoryAllStopsOnEmptyPage(t *testing.T) {
	p := &pagedServer{rows: []string{row(uuidN(1)), row(uuidN(2))}, total: 50}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	ids, err := collect(t, c, &HistoryIterateOptions{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || srv.Count() != 2 {
		t.Errorf("ids = %v, requests = %d", ids, srv.Count())
	}
}

func TestHistoryAllMaxItemsAndBreak(t *testing.T) {
	rows := []string{}
	for i := 1; i <= 10; i++ {
		rows = append(rows, row(uuidN(i)))
	}
	p := &pagedServer{rows: rows}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)

	ids, err := collect(t, c, &HistoryIterateOptions{PageSize: 2, MaxItems: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || srv.Count() != 2 {
		t.Errorf("MaxItems: ids = %v, requests = %d", ids, srv.Count())
	}

	before := srv.Count()
	n := 0
	for ident, err := range c.History.All(context.Background(), LookupDeviceID, uuidN(99), &HistoryIterateOptions{PageSize: 2}) {
		if err != nil || ident == nil {
			t.Fatal(err)
		}
		n++
		if n == 3 {
			break
		}
	}
	if srv.Count()-before != 2 {
		t.Errorf("break: %d requests after the loop ended", srv.Count()-before)
	}
}

func TestHistoryAllErrors(t *testing.T) {
	p := &pagedServer{
		rows: []string{row(uuidN(1)), row(uuidN(2)), row(uuidN(3))},
		overrides: map[int]func(w http.ResponseWriter){
			2: func(w http.ResponseWriter) { http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized) },
		},
	}
	srv := newRecordingServer(t, p.handler)
	c, _ := newTestClient(t, srv.URL)
	ids, err := collect(t, c, &HistoryIterateOptions{PageSize: 2})
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("rows before the error: %v", ids)
	}

	invalid := []struct {
		lookup LookupType
		value  string
		opts   *HistoryIterateOptions
	}{
		{"phone", "1", nil},
		{LookupIP, "2001:db8::2", nil},
		{LookupUserHID, "", nil},
		{LookupUserHID, "a/b", nil},
		{LookupUserHID, ".", nil},
		{LookupUserHID, "..", nil},
		{LookupDeviceID, uuidN(1), &HistoryIterateOptions{PageSize: 101}},
		{LookupDeviceID, uuidN(1), &HistoryIterateOptions{PageSize: -1}},
		{LookupDeviceID, uuidN(1), &HistoryIterateOptions{MaxItems: -1}},
	}
	before := srv.Count()
	for _, tc := range invalid {
		calls := 0
		for ident, err := range c.History.All(context.Background(), tc.lookup, tc.value, tc.opts) {
			calls++
			if ident != nil || !errors.Is(err, ErrValidation) {
				t.Errorf("%v: got %v, %v", tc, ident, err)
			}
		}
		if calls != 1 {
			t.Errorf("%v: yielded %d times", tc, calls)
		}
	}
	if srv.Count() != before {
		t.Error("validation errors must not send requests")
	}
}

func TestHistoryUnreadablePage(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	})
	c, _ := newTestClient(t, srv.URL)
	_, err := c.History.Search(context.Background(), LookupDeviceID, uuidN(1), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 200 || isTransient(err) {
		t.Fatalf("err = %v", err)
	}
	if srv.Count() != 1 {
		t.Errorf("an unreadable 200 must not be retried, got %d requests", srv.Count())
	}

	// Non-object rows are skipped and a missing data array is an empty page.
	srv2 := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			writeJSON(w, 200, `{"data":[1,"x",`+row(uuidN(1))+`],"total":"3"}`)
			return
		}
		writeJSON(w, 200, `{"total":0}`)
	})
	c2, _ := newTestClient(t, srv2.URL)
	page, err := c2.History.Search(context.Background(), LookupDeviceID, uuidN(1), nil)
	if err != nil || len(page.Data) != 1 || page.Total != 0 {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	page, err = c2.History.Search(context.Background(), LookupDeviceID, uuidN(1), nil)
	if err != nil || page.Data == nil || len(page.Data) != 0 {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
}
