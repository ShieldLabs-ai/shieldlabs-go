package shieldlabs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhook_valid(t *testing.T) {
	secret := "whsec_test_secret"
	body := []byte(`{"event_type":"webhook.ping","schema_version":"2026-06-01","created_at":"2026-06-26T14:20:42Z"}`)
	if !VerifyWebhook(body, sign(secret, body), secret) {
		t.Fatal("expected valid signature")
	}
}

func TestVerifyWebhook_wrongSecret(t *testing.T) {
	secret := "whsec_test_secret"
	body := []byte(`{"event_type":"webhook.ping"}`)
	if VerifyWebhook(body, sign(secret, body), "other") {
		t.Fatal("expected rejection")
	}
}

func TestVerifyWebhook_tamperedBody(t *testing.T) {
	secret := "whsec_test_secret"
	body := []byte(`{"event_type":"webhook.ping"}`)
	if VerifyWebhook(append(body, ' '), sign(secret, body), secret) {
		t.Fatal("expected rejection")
	}
}

func TestVerifyWebhook_missingHeader(t *testing.T) {
	if VerifyWebhook([]byte("{}"), "", "secret") {
		t.Fatal("expected rejection")
	}
}

func TestVerifyWebhook_truncated(t *testing.T) {
	secret := "whsec_test_secret"
	body := []byte(`{}`)
	if VerifyWebhook(body, "sha256=ab", secret) {
		t.Fatal("expected rejection")
	}
}

func TestVerifyWebhook_emptySecret(t *testing.T) {
	body := []byte(`{}`)
	if VerifyWebhook(body, sign("x", body), "") {
		t.Fatal("expected rejection")
	}
}
