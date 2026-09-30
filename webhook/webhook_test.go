package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
)

const realSecret = "whsec_00112233445566778899aabbccddeeff"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type vector struct {
	Name            string   `json:"name"`
	Secret          *string  `json:"secret"`
	Secrets         []string `json:"secrets"`
	Body            string   `json:"body"`
	BodyBase64      string   `json:"body_base64"`
	SignatureHeader string   `json:"signature_header"`
	Valid           bool     `json:"valid"`
}

func TestSignatureVectors(t *testing.T) {
	var f struct {
		HeaderName string   `json:"header_name"`
		Vectors    []vector `json:"vectors"`
	}
	if err := json.Unmarshal(readFixture(t, "webhook-signature-vectors.json"), &f); err != nil {
		t.Fatal(err)
	}
	if f.HeaderName != SignatureHeader {
		t.Errorf("header name %q, want %q", f.HeaderName, SignatureHeader)
	}
	if len(f.Vectors) != 21 {
		t.Fatalf("want 21 vectors, got %d", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			body, err := base64.StdEncoding.DecodeString(v.BodyBase64)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != v.Body {
				t.Fatal("body and body_base64 disagree")
			}
			var secrets []string
			switch {
			case v.Secret != nil && v.Secrets == nil:
				secrets = []string{*v.Secret}
			case v.Secret == nil && v.Secrets != nil:
				secrets = v.Secrets
			default:
				t.Fatal("a vector has either secret or secrets")
			}
			if got := VerifySignature(body, v.SignatureHeader, secrets...); got != v.Valid {
				t.Errorf("VerifySignature = %v, want %v", got, v.Valid)
			}
			_, err = ConstructEvent(body, v.SignatureHeader, secrets...)
			if v.Valid && errors.Is(err, ErrSignature) {
				t.Errorf("ConstructEvent rejected a valid signature: %v", err)
			}
			if !v.Valid && !errors.Is(err, ErrSignature) {
				t.Errorf("ConstructEvent: err = %v, want ErrSignature", err)
			}
		})
	}
}

func TestVerifySignatureSecretLists(t *testing.T) {
	body := readFixture(t, "webhook-ping.raw.txt")
	header := sign(realSecret, body)
	if VerifySignature(body, header) {
		t.Error("no secrets must never verify")
	}
	if VerifySignature(body, header, "", "") {
		t.Error("empty secrets must never verify")
	}
	if !VerifySignature(body, header, "", "whsec_other", realSecret) {
		t.Error("any matching secret verifies")
	}
	if !VerifySignature(body, "SHA256="+header[len("sha256="):], realSecret) {
		t.Error("the prefix is compared case-insensitively")
	}
	if VerifySignature(body, header+" extra", realSecret) {
		t.Error("trailing garbage must fail")
	}
}

func TestConstructScoredEvent(t *testing.T) {
	body := readFixture(t, "webhook-identification-scored.raw.txt")
	event, err := ConstructEvent(body, sign(realSecret, body), realSecret)
	if err != nil {
		t.Fatal(err)
	}
	scored, ok := event.(*IdentificationScoredEvent)
	if !ok {
		t.Fatalf("event = %T", event)
	}
	if scored.Type() != EventTypeIdentificationScored || scored.EventType != EventTypeIdentificationScored {
		t.Errorf("type = %q", scored.Type())
	}
	if scored.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %q", scored.SchemaVersion)
	}
	if got := scored.CreatedAt.Format(time.RFC3339Nano); got != "2026-09-30T12:34:57.482913041Z" {
		t.Errorf("created_at = %s", got)
	}
	assertMatchesCase(t, scored.Data, "webhook_scored")
	if scored.Data.TrafficSource.LandingURL != "https://shop.example.com/signup?utm_source=google&utm_medium=cpc&gclid=abc123" {
		t.Errorf("escaped ampersands must decode: %q", scored.Data.TrafficSource.LandingURL)
	}
	if scored.Raw["event_type"] != EventTypeIdentificationScored {
		t.Error("Raw holds the whole body")
	}
	if scored.Data.Raw["request_id"] != "02f1d973-84db-4156-a7f7-e799e6bf389b" {
		t.Error("Data.Raw holds the data object")
	}
}

func TestConstructPrettyScoredRateLimitedAndTestDeliveries(t *testing.T) {
	cases := map[string]string{
		"webhook-identification-scored.json": "webhook_scored",
		"webhook-rate-limited.json":          "webhook_rate_limited",
		"webhook-test-delivery.json":         "webhook_test_delivery",
	}
	for file, caseName := range cases {
		body := readFixture(t, file)
		event, err := ConstructEvent(body, sign(realSecret, body), realSecret)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		scored, ok := event.(*IdentificationScoredEvent)
		if !ok {
			t.Fatalf("%s: event = %T", file, event)
		}
		assertMatchesCase(t, scored.Data, caseName)
	}

	// The analytics dashboard test delivery has 17 of the 19 flags and
	// second-precision timestamps.
	body := readFixture(t, "webhook-test-delivery.json")
	var raw struct {
		Data struct {
			DetectionFlags map[string]bool `json:"detection_flags"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Data.DetectionFlags) != 17 {
		t.Fatalf("fixture has %d flags, want 17", len(raw.Data.DetectionFlags))
	}
	event, _ := ConstructEvent(body, sign(realSecret, body), realSecret)
	data := event.(*IdentificationScoredEvent).Data
	if data.DetectionFlags.BrowserAutomation || data.DetectionFlags.SearchBot {
		t.Error("missing flags default to false")
	}
	if data.UserHID != nil {
		t.Error("user_hid null stays nil")
	}
	if got := data.ObservedAt.Format(time.RFC3339Nano); got != "2026-09-30T12:34:56Z" {
		t.Errorf("observed_at = %s", got)
	}
	if data.PublicIP.Country != "BY" || data.RiskScore != 30 || data.Band() != shieldlabs.BandSuspicious {
		t.Errorf("sample values: %+v", data)
	}
}

func TestConstructPingEvent(t *testing.T) {
	body := readFixture(t, "webhook-ping.raw.txt")
	header := "sha256=ea2685733d254f7028fb031c4214583b0650de01e6c8c93131236024edd9fdd8"
	event, err := ConstructEvent(body, header, realSecret)
	if err != nil {
		t.Fatal(err)
	}
	ping, ok := event.(*PingEvent)
	if !ok {
		t.Fatalf("event = %T", event)
	}
	if ping.Type() != EventTypePing || ping.SchemaVersion != "2026-06-01" {
		t.Errorf("ping = %+v", ping.Envelope)
	}
	if got := ping.CreatedAt.Format(time.RFC3339); got != "2026-09-30T12:34:56Z" {
		t.Errorf("created_at = %s", got)
	}
	// The pretty-printed ping fixture parses the same way once signed.
	pretty := readFixture(t, "webhook-ping.json")
	event, err = ConstructEvent(pretty, sign(realSecret, pretty), realSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := event.(*PingEvent); !ok {
		t.Fatalf("event = %T", event)
	}
}

func TestConstructUnknownEvent(t *testing.T) {
	body := []byte(`{"event_type":"identification.refined","schema_version":"2027-01-01","created_at":"not a time","data":{"x":1},"extra":[1,2]}`)
	event, err := ConstructEvent(body, sign(realSecret, body), realSecret)
	if err != nil {
		t.Fatal(err)
	}
	unknown, ok := event.(*UnknownEvent)
	if !ok {
		t.Fatalf("event = %T", event)
	}
	if unknown.Type() != "identification.refined" || unknown.SchemaVersion != "2027-01-01" || !unknown.CreatedAt.IsZero() {
		t.Errorf("unknown = %+v", unknown.Envelope)
	}
	if unknown.Raw["extra"] == nil {
		t.Error("Raw keeps unknown fields")
	}

	// Unknown schema versions of known events are accepted.
	scored := []byte(`{"event_type":"identification.scored","schema_version":"2099-12-31","created_at":"2026-09-30T12:00:00Z","data":{"request_id":"3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53","risk_score":35,"new_field":true}}`)
	event, err = ConstructEvent(scored, sign(realSecret, scored), realSecret)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := event.(*IdentificationScoredEvent); !ok || e.Data.RiskScore != 35 || e.SchemaVersion != "2099-12-31" {
		t.Errorf("event = %#v", event)
	}
}

func TestConstructEventParseErrors(t *testing.T) {
	bodies := []string{
		``,
		`not json`,
		`[]`,
		`null`,
		`{"event_type":"identification.scored"} trailing`,
		`{"schema_version":"2026-06-01"}`,
		`{"event_type":42}`,
		`{"event_type":""}`,
		`{"event_type":"identification.scored","schema_version":"2026-06-01"}`,
		`{"event_type":"identification.scored","data":null}`,
		`{"event_type":"identification.scored","data":[1,2]}`,
		`{"event_type":"identification.scored","data":"x"}`,
	}
	for _, b := range bodies {
		body := []byte(b)
		_, err := ConstructEvent(body, sign(realSecret, body), realSecret)
		if !errors.Is(err, ErrParse) || errors.Is(err, ErrSignature) {
			t.Errorf("%q: err = %v, want ErrParse", b, err)
		}
	}
	// The signature is checked before the body is parsed.
	if _, err := ConstructEvent([]byte(`not json`), "sha256=00", realSecret); !errors.Is(err, ErrSignature) {
		t.Errorf("err = %v", err)
	}
}

func TestSignatureErrorMessages(t *testing.T) {
	body := []byte(`{}`)
	tests := map[string][]string{
		"":                                     {realSecret},
		"md5=abc":                              {realSecret},
		"sha256=abc":                           {realSecret},
		"sha256=" + sign(realSecret, body)[7:]: {},
	}
	for header, secrets := range tests {
		err := verify(body, header, secrets)
		if !errors.Is(err, ErrSignature) || err.Error() == ErrSignature.Error() {
			t.Errorf("header %q: err = %v (want a reason)", header, err)
		}
	}
}

func assertMatchesCase(t *testing.T, got *shieldlabs.Identification, caseName string) {
	t.Helper()
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "normalization-cases.json"), &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		if c.Name != caseName {
			continue
		}
		var want map[string]any
		if err := json.Unmarshal(c.Expected, &want); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var view map[string]any
		if err := json.Unmarshal(b, &view); err != nil {
			t.Fatal(err)
		}
		view["observed_at"] = got.ObservedAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
		if !reflect.DeepEqual(view, want) {
			gotJSON, _ := json.MarshalIndent(view, "", "  ")
			wantJSON, _ := json.MarshalIndent(want, "", "  ")
			t.Errorf("%s differs:\ngot  %s\nwant %s", caseName, gotJSON, wantJSON)
		}
		return
	}
	t.Fatalf("case %s not found", caseName)
}
