package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
	"github.com/ShieldLabs-ai/shieldlabs-go/webhook"
)

const (
	testKey    = "sec_abcd1234-efgh5678-ijkl9012"
	testSecret = "whsec_00112233445566778899aabbccddeeff"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// historyServer answers History lookups by request ID from rows built on
// the fly, so that every identification is fresh.
func historyServer(t *testing.T, rows map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		id := parts[len(parts)-1]
		w.Header().Set("Content-Type", "application/json")
		extra, ok := rows[id]
		if !ok {
			_, _ = io.WriteString(w, `{"data":[],"total":0}`)
			return
		}
		created := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		_, _ = fmt.Fprintf(w, `{"data":[{"request_id":%q,"device_id":"ac7c303d-971b-41d1-8e25-cd5b46b46aed","created_at":%q%s}],"total":1}`, id, created, extra)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestApp(t *testing.T, rows map[string]string) http.Handler {
	t.Helper()
	srv := historyServer(t, rows)
	client, err := shieldlabs.NewClient(testKey, shieldlabs.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return newApp(client, []string{testSecret}, 200*time.Millisecond).routes()
}

func postSignup(t *testing.T, h http.Handler, body string, contentType string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSignupPolicy(t *testing.T) {
	const (
		trusted    = "11111111-1111-4111-8111-111111111111"
		dangerous  = "22222222-2222-4222-8222-222222222222"
		automation = "33333333-3333-4333-8333-333333333333"
		limited    = "44444444-4444-4444-8444-444444444444"
		missing    = "55555555-5555-4555-8555-555555555555"
		formPosted = "66666666-6666-4666-8666-666666666666"
	)
	h := newTestApp(t, map[string]string{
		trusted:    `,"score":10`,
		dangerous:  `,"score":80`,
		automation: `,"score":60,"is_browser_automation":true`,
		limited:    `,"score":999`,
		formPosted: `,"score":5`,
	})

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantReason string
	}{
		{"trusted", `{"requestId":"` + trusted + `"}`, 200, ""},
		{"reuse", `{"requestId":"` + trusted + `"}`, 403, "replayed"},
		{"dangerous band", `{"requestId":"` + dangerous + `"}`, 403, "blocked_band"},
		{"automation flag", `{"requestId":"` + automation + `"}`, 403, "blocked_flag"},
		{"rate limited", `{"requestId":"` + limited + `"}`, 403, "rate_limited"},
		{"missing", `{"requestId":"` + missing + `"}`, 403, "missing"},
		{"invalid id", `{"requestId":"abc"}`, 400, ""},
		{"no id", `{}`, 400, ""},
		{"bad json", `{`, 400, ""},
	}
	for _, tc := range tests {
		status, out := postSignup(t, h, tc.body, "application/json")
		if status != tc.wantStatus {
			t.Errorf("%s: status %d, want %d (%v)", tc.name, status, tc.wantStatus, out)
		}
		if tc.wantReason != "" && out["reason"] != tc.wantReason {
			t.Errorf("%s: reason %v, want %s", tc.name, out["reason"], tc.wantReason)
		}
	}

	status, out := postSignup(t, h, url.Values{"requestId": {formPosted}}.Encode(), "application/x-www-form-urlencoded")
	if status != 200 || out["ok"] != true {
		t.Errorf("form post: %d %v", status, out)
	}
}

func TestSignupUnverifiedWhenTheAPIFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	client, err := shieldlabs.NewClient(testKey, shieldlabs.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	h := newApp(client, []string{testSecret}, time.Second).routes()
	status, out := postSignup(t, h, `{"requestId":"11111111-1111-4111-8111-111111111111"}`, "application/json")
	if status != http.StatusServiceUnavailable || out["reason"] != "unverified" {
		t.Errorf("status %d %v", status, out)
	}
}

func sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(h http.Handler, body []byte, signature string) int {
	req := httptest.NewRequest(http.MethodPost, "/webhooks/shieldlabs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.SignatureHeader, signature)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestWebhookHandler(t *testing.T) {
	h := newTestApp(t, nil)
	scored, err := os.ReadFile("../../testdata/webhook-identification-scored.raw.txt")
	if err != nil {
		t.Fatal(err)
	}
	ping, err := os.ReadFile("../../testdata/webhook-ping.raw.txt")
	if err != nil {
		t.Fatal(err)
	}
	unknown := []byte(`{"event_type":"identification.refined","schema_version":"2026-06-01","created_at":"2026-09-30T12:00:00Z"}`)
	invalid := []byte(`{"schema_version":"2026-06-01"}`)

	tests := []struct {
		name      string
		body      []byte
		signature string
		want      int
	}{
		{"scored", scored, sign(scored), 200},
		{"duplicate delivery", scored, sign(scored), 200},
		{"ping", ping, sign(ping), 200},
		{"unknown event", unknown, sign(unknown), 200},
		{"bad signature", scored, sign(ping), 401},
		{"missing signature", scored, "", 401},
		{"invalid payload", invalid, sign(invalid), 400},
	}
	for _, tc := range tests {
		if got := postWebhook(h, tc.body, tc.signature); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestRecentSet(t *testing.T) {
	s := newRecentSet(time.Hour)
	if s.seenBefore("a") || !s.seenBefore("a") || s.seenBefore("b") {
		t.Error("seenBefore")
	}
	expired := newRecentSet(-time.Second)
	first := expired.seenBefore("a")
	second := expired.seenBefore("a")
	if first || second {
		t.Error("expired keys are forgotten")
	}
}
