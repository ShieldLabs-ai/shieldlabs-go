package shieldlabs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

func TestGetProfileFixture(t *testing.T) {
	body := readFixture(t, "management-profile.json")
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
	})
	m, err := NewManagementClient(" "+testSecretKey+"\n", "https://www.Example.com/", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := m.GetProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var want map[string]any
	if err := json.Unmarshal(readFixture(t, "management-profile-expected.json"), &want); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(profile)
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	got["created_at"] = profile.CreatedAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("profile = %s\nwant %s", mustJSON(got), mustJSON(want))
	}
	wantRaw, _ := wire.DecodeObject(body)
	if !reflect.DeepEqual(profile.Raw, wantRaw) {
		t.Error("Raw must hold the original response, including Callback")
	}
	if _, ok := profile.Raw["Callback"]; !ok {
		t.Error("the legacy Callback field stays in Raw")
	}

	req := srv.Request(0)
	if req.Method != http.MethodGet || req.URL.EscapedPath() != "/v1/profile" || req.URL.RawQuery != "" {
		t.Errorf("request %s %s?%s", req.Method, req.URL.EscapedPath(), req.URL.RawQuery)
	}
	if got := req.Header.Get("X-Shield-Domain"); got != "example.com" {
		t.Errorf("X-Shield-Domain = %q", got)
	}
	assertStandardHeaders(t, req, "Bearer "+testSecretKey)
}

func TestGetProfileNegativeWeightAndZeroTime(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, `{"Domain":"example.com","Weight":-1250,"PublicKey":"","Secret":"abcd","CreatedAt":"0001-01-01T00:00:00Z","Extra":true}`)
	})
	m, _ := newTestManagementClient(t, srv.URL)
	p, err := m.GetProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.RemainingIdentifications != -1250 || !p.CreatedAt.IsZero() || p.SecretKeyMasked != "abcd" || p.PublicKeyMasked != "" {
		t.Errorf("profile = %+v", p)
	}
}

func TestGetProfileUnreadableBody(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, `["not","a","profile"]`)
	})
	m, _ := newTestManagementClient(t, srv.URL)
	_, err := m.GetProfile(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 200 {
		t.Fatalf("err = %v", err)
	}
}

func TestManagementNeverRetriesRateLimit(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Retry-After", "600")
		writeJSON(w, 429, `{"error":"too many requests"}`)
	})
	m, clk := newTestManagementClient(t, srv.URL, WithMaxRetries(5))
	_, err := m.GetProfile(context.Background())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 10*time.Minute || apiErr.Message != "too many requests" {
		t.Errorf("APIError = %+v", apiErr)
	}
	if srv.Count() != 1 || len(clk.Sleeps()) != 0 {
		t.Errorf("requests = %d, waits = %v; a Management 429 must never be retried", srv.Count(), clk.Sleeps())
	}
}

func TestManagementRetriesServerErrors(t *testing.T) {
	profile := readFixture(t, "management-profile.json")
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n < 3 {
			writeJSON(w, 503, `{"error":"server is busy"}`)
			return
		}
		_, _ = w.Write(profile)
	})
	m, _ := newTestManagementClient(t, srv.URL)
	if _, err := m.GetProfile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.Count() != 3 {
		t.Errorf("requests = %d", srv.Count())
	}
}

func TestManagementBaseURLKeepsAPISegment(t *testing.T) {
	profile := readFixture(t, "management-profile.json")
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		_, _ = w.Write(profile)
	})
	m, _ := newTestManagementClient(t, srv.URL+"/api/")
	if _, err := m.GetProfile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.Request(0).URL.EscapedPath(); got != "/api/v1/profile" {
		t.Errorf("path %s: only the History client strips /api", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := map[string]string{
		"example.com":                        "example.com",
		"  EXAMPLE.com  ":                    "example.com",
		"https://www.Example.com/":           "example.com",
		"http://example.com/path/page?x=1#y": "example.com",
		"www.shop.example.com":               "shop.example.com",
		"shop.example.com/":                  "shop.example.com",
		"example.com:8443":                   "example.com:8443",
		"HTTPS://WWW.EXAMPLE.COM?utm=1":      "example.com",
		"example.com#fragment":               "example.com",
		"wwwexample.com":                     "wwwexample.com",
		"https://":                           "",
		"   ":                                "",
	}
	for in, want := range tests {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewManagementClientValidation(t *testing.T) {
	tests := []struct {
		secret, domain string
		opts           []Option
	}{
		{"", "example.com", nil},
		{"  ", "example.com", nil},
		{testSecretKey, "", nil},
		{testSecretKey, "https://", nil},
		{testSecretKey, "example.com", []Option{WithTimeout(-time.Second)}},
		{testSecretKey, "example.com", []Option{WithBaseURL("example.com")}},
		{testSecretKey, "example.com", []Option{WithBaseURL("http://api.shieldlabs.ai")}},
		{"0123456789abcdef\n0123456789abcdef", "example.com", nil},
		{"0123456789abcdef 0123456789abcdef", "example.com", nil},
		{"0123456789abcdef0123456789abcdef\x00", "example.com", nil},
		{testSecretKey, "exam ple.com", nil},
		{testSecretKey, "example.com\x00", nil},
		{testSecretKey, "example\n.com", nil},
	}
	for _, tc := range tests {
		_, err := NewManagementClient(tc.secret, tc.domain, tc.opts...)
		if !errors.Is(err, ErrValidation) {
			t.Errorf("NewManagementClient(%q, %q): err = %v", tc.secret, tc.domain, err)
			continue
		}
		if strings.Contains(err.Error(), "0123456789abcdef") {
			t.Errorf("the error must not contain the Secret Key: %v", err)
		}
	}
}
