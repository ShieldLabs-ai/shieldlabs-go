package shieldlabs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type errorCase struct {
	Surface       string  `json:"surface"`
	Status        int     `json:"status"`
	ContentType   *string `json:"content_type"`
	Body          string  `json:"body"`
	ExpectedError string  `json:"expected_error"`
	Retry         bool    `json:"retry"`
}

var errorClasses = map[string]error{
	"BadRequestError":     ErrBadRequest,
	"AuthenticationError": ErrAuthentication,
	"QuotaExceededError":  ErrQuotaExceeded,
	"NotFoundError":       ErrNotFound,
	"RateLimitError":      ErrRateLimited,
	"ServerError":         ErrServer,
}

func TestErrorResponsesFixture(t *testing.T) {
	var f struct {
		Cases []errorCase `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "error-responses.json"), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	surfaces := map[string]int{}
	for _, tc := range f.Cases {
		surfaces[tc.Surface]++
		name := tc.Surface + "_" + tc.ExpectedError + "_" + http.StatusText(tc.Status)
		t.Run(name, func(t *testing.T) {
			sentinel, ok := errorClasses[tc.ExpectedError]
			if !ok {
				t.Fatalf("unmapped error class %s", tc.ExpectedError)
			}
			srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
				if tc.ContentType == nil {
					w.Header()["Content-Type"] = nil // no Content-Type, no sniffing
				} else {
					w.Header().Set("Content-Type", *tc.ContentType)
				}
				w.WriteHeader(tc.Status)
				_, _ = io.WriteString(w, tc.Body)
			})

			var err error
			var clk *fakeClock
			switch tc.Surface {
			case "history":
				var c *Client
				c, clk = newTestClient(t, srv.URL)
				_, err = c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil)
			case "management":
				var m *ManagementClient
				m, clk = newTestManagementClient(t, srv.URL)
				_, err = m.GetProfile(context.Background())
			default:
				t.Fatalf("unknown surface %s", tc.Surface)
			}

			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want %v", err, sentinel)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T, want *APIError", err)
			}
			if apiErr.StatusCode != tc.Status || string(apiErr.Body) != tc.Body {
				t.Errorf("status %d body %q", apiErr.StatusCode, apiErr.Body)
			}
			for other, s := range errorClasses {
				if other != tc.ExpectedError && errors.Is(err, s) {
					t.Errorf("error also matches %s", other)
				}
			}
			wantRequests := 1
			if tc.Retry {
				wantRequests = 1 + defaultMaxRetries
			}
			if srv.Count() != wantRequests {
				t.Errorf("requests = %d, want %d (retry = %v)", srv.Count(), wantRequests, tc.Retry)
			}
			if len(clk.Sleeps()) != wantRequests-1 {
				t.Errorf("waits = %v", clk.Sleeps())
			}
		})
	}
	if surfaces["history"] == 0 || surfaces["management"] == 0 {
		t.Fatalf("fixture must cover both surfaces: %v", surfaces)
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{"", ""},
		{"   \n", ""},
		{`{"error":"invalid api key"}` + "\n", "invalid api key"},
		{`{"message":"try later"}`, "try later"},
		{`{"error":""}`, ""},
		{`{"error":5}`, ""},
		{`"fail parse uuid"`, "fail parse uuid"},
		{`null`, ""},
		{`42`, ""},
		{"404 page not found", "404 page not found"},
		{"<html><body>502</body></html>", ""},
		{"\xff\xfe", ""},
		{strings.Repeat("é", 150), strings.Repeat("é", 100) + "..."},
	}
	for _, tc := range tests {
		if got := errorMessage([]byte(tc.body)); got != tc.want {
			t.Errorf("errorMessage(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestAPIErrorString(t *testing.T) {
	e := newAPIError(429, http.Header{"Retry-After": {"2"}}, []byte(`{"error":"too many requests"}`), time.Now())
	if got := e.Error(); got != "shieldlabs: HTTP 429 Too Many Requests: too many requests" {
		t.Errorf("Error() = %q", got)
	}
	if e.RetryAfter != 2*time.Second {
		t.Errorf("RetryAfter = %s", e.RetryAfter)
	}
	e = newAPIError(499, nil, nil, time.Now())
	if got := e.Error(); got != "shieldlabs: HTTP 499" {
		t.Errorf("Error() = %q", got)
	}
	for _, s := range errorClasses {
		if errors.Is(e, s) {
			t.Errorf("status 499 must not match %v", s)
		}
	}
	if !errors.Is(newAPIError(403, nil, nil, time.Now()), ErrAuthentication) {
		t.Error("403 is an authentication error")
	}
	if !errors.Is(newAPIError(504, nil, nil, time.Now()), ErrServer) {
		t.Error("504 is a server error")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	valid := map[string]time.Duration{
		"3":                             3 * time.Second,
		" 1.5 ":                         1500 * time.Millisecond,
		"0.25":                          250 * time.Millisecond,
		"600":                           10 * time.Minute,
		"99999999":                      99999999 * time.Second,
		"Wed, 30 Sep 2026 12:00:05 GMT": 5 * time.Second,
		// Delays too long for a time.Duration saturate.
		"100000000000":                  math.MaxInt64,
		"1" + strings.Repeat("0", 400):  math.MaxInt64,
		"Fri, 31 Dec 9999 23:59:59 GMT": math.MaxInt64,
		// No delay: 0 and a date that is not in the future are valid and ask
		// for an immediate retry.
		"0":                             0,
		"0.0":                           0,
		"Wed, 30 Sep 2026 12:00:00 GMT": 0,
		"Wed, 30 Sep 2026 11:00:00 GMT": 0,
		"Wed, 21 Oct 2015 07:28:00 GMT": 0,
	}
	for in, want := range valid {
		if got, ok := parseRetryAfter(in, now); got != want || !ok {
			t.Errorf("parseRetryAfter(%q) = %s, %v, want %s, true", in, got, ok, want)
		}
	}
	// No header, or a value that is not a delay in seconds or an HTTP date.
	for _, in := range []string{"", "   ", "abc", "soon", "-4", "-0", "+5", "1e3", ".5", "5.", "1 2", "NaN", "Inf", "+Inf", "-Inf", "0x10"} {
		if got, ok := parseRetryAfter(in, now); got != 0 || ok {
			t.Errorf("parseRetryAfter(%q) = %s, %v, want 0, false", in, got, ok)
		}
	}
}

func TestAPIErrorKeepsWhetherRetryAfterWasSent(t *testing.T) {
	now := time.Now()
	for value, sent := range map[string]bool{"0": true, "Wed, 21 Oct 2015 07:28:00 GMT": true, "2": true, "soon": false, "-1": false} {
		e := newAPIError(429, http.Header{"Retry-After": {value}}, nil, now)
		if e.retryAfterSent != sent {
			t.Errorf("Retry-After %q: sent = %v, want %v", value, e.retryAfterSent, sent)
		}
	}
	if newAPIError(429, http.Header{}, nil, now).retryAfterSent || newAPIError(429, nil, nil, now).retryAfterSent {
		t.Error("no Retry-After header must not count as sent")
	}
}
