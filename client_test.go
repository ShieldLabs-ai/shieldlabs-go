package shieldlabs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewClientValidation(t *testing.T) {
	for _, key := range []string{"", "   ", "\n"} {
		if _, err := NewClient(key); !errors.Is(err, ErrValidation) {
			t.Errorf("key %q: err = %v", key, err)
		}
	}
	// Whitespace or control characters inside the key come from a bad copy
	// and paste; they are reported as invalid, not as a network failure, and
	// the error never repeats the key.
	for _, key := range []string{
		"sec_abcd1234-efgh5678\n-ijkl9012",
		"sec_abcd1234 efgh5678-ijkl9012",
		"sec_abcd1234-efgh5678-ijkl9012\x00",
		"sec_abcd1234-efgh5678-ijkl9012\x7f",
		"sec_abcd1234-efgh5678- ijkl9012",
	} {
		_, err := NewClient(key)
		if !errors.Is(err, ErrValidation) {
			t.Errorf("key %q: err = %v", key, err)
			continue
		}
		if strings.Contains(err.Error(), "abcd1234") {
			t.Errorf("the error must not contain the key: %v", err)
		}
	}
	for _, opt := range []Option{WithTimeout(-time.Second), WithMaxRetries(-1), WithBaseURL("nope")} {
		if _, err := NewClient(testAPIKey, opt); !errors.Is(err, ErrValidation) {
			t.Errorf("option: err = %v", err)
		}
	}
}

func TestNewClientWarnsOnUnexpectedKeyFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if _, err := NewClient(testAPIKey, WithLogger(logger)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("a valid key must not warn: %s", buf.String())
	}

	c, err := NewClient("0123456789abcdef0123456789abcdef", WithLogger(logger))
	if err != nil || c == nil {
		t.Fatalf("an unexpected key format must not fail: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "Private API Key") {
		t.Errorf("warning = %q", out)
	}
	if strings.Contains(out, "0123456789abcdef") {
		t.Error("the warning must never contain the key")
	}
}

func TestNewClientTrimsKeyAndAcceptsNilOptions(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, emptyPage)
	})
	c, err := NewClient("  "+testAPIKey+"\n", nil, WithBaseURL(srv.URL), WithHTTPClient(nil), WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err != nil {
		t.Fatal(err)
	}
	if got := srv.Request(0).Header.Get("Authorization"); got != "Bearer "+testAPIKey {
		t.Errorf("Authorization = %q", got)
	}
}

func TestCustomHTTPClientIsUsed(t *testing.T) {
	used := false
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})}
	c, err := NewClient(testAPIKey, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	// An empty 200 body is not a History page.
	if _, err := c.History.Search(context.Background(), LookupDeviceID, NilUUID, nil); err == nil {
		t.Error("expected an error for an empty body")
	}
	if !used {
		t.Error("the injected http.Client was not used")
	}
}

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	page := rowPage(t)
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeJSON(w, 200, page)
	})
	c, _ := newTestClient(t, srv.URL)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, err := c.Identifications.Get(context.Background(), testRequestID, nil)
			errs <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
