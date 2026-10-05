// Package webhook verifies and parses ShieldLabs webhook deliveries.
//
// ShieldLabs signs every delivery with the endpoint's signing secret:
//
//	X-Shield-Signature: sha256=<lowercase hex HMAC-SHA256(secret, raw body)>
//
// The key is the whole secret string including its "whsec_" prefix, and the
// message is the raw request body exactly as received. Always verify the raw
// bytes: parsing and re-encoding the JSON changes them.
//
// Version 2026-10-06 carries a signed event_id in the body and an
// X-Shield-Event-Id header. Failed deliveries are retried within a bounded
// retry window. Deduplicate by EventID, persist the event before replying
// with 2xx, and process asynchronously. Legacy events without EventID may
// fall back to Data.RequestID. Use History for latest state/recovery.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// SignatureHeader is the HTTP header that carries the signature.
const SignatureHeader = "X-Shield-Signature"

// Event types.
const (
	// EventTypeIdentificationScored is sent when an identification has been
	// scored, and by the "Test" button of the analytics dashboard.
	EventTypeIdentificationScored = "identification.scored"
	// EventTypePing is sent by the "Verify" button of the analytics
	// dashboard.
	EventTypePing = "webhook.ping"
)

// SchemaVersion is the schema version of the events this package was built
// for. Deliveries with other schema versions are accepted.
const SchemaVersion = "2026-10-06"

var (
	// ErrSignature reports a missing, malformed or non-matching signature,
	// or no usable secret. Answer such requests with 401.
	ErrSignature = errors.New("shieldlabs/webhook: signature verification failed")

	// ErrParse reports a verified body that is not a valid event (invalid
	// JSON, not an object, no event type, or a scored event without data).
	ErrParse = errors.New("shieldlabs/webhook: invalid event payload")
)

const signaturePrefix = "sha256="

// VerifySignature reports whether header is a valid X-Shield-Signature value
// for payload under any of the given secrets. Pass the raw request body and
// the full secret strings (with their "whsec_" prefix). Several secrets let
// you rotate the endpoint secret without downtime.
//
// The comparison runs in constant time. Surrounding whitespace and upper-case
// hex digits in the header are accepted. A missing "sha256=" prefix, a digest
// that is not 64 hex characters, an empty header or no non-empty secret
// always fails. Empty secrets in the list are ignored.
func VerifySignature(payload []byte, header string, secrets ...string) bool {
	return verify(payload, header, secrets) == nil
}

func verify(payload []byte, header string, secrets []string) error {
	h := strings.ToLower(strings.TrimSpace(header))
	if h == "" {
		return fmt.Errorf("%w: the %s header is missing", ErrSignature, SignatureHeader)
	}
	if !strings.HasPrefix(h, signaturePrefix) {
		return fmt.Errorf("%w: the signature must start with %q", ErrSignature, signaturePrefix)
	}
	digestHex := h[len(signaturePrefix):]
	if len(digestHex) != 2*sha256.Size {
		return fmt.Errorf("%w: the digest must be %d hex characters", ErrSignature, 2*sha256.Size)
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return fmt.Errorf("%w: the digest is not hexadecimal", ErrSignature)
	}
	usable := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		usable = true
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		if hmac.Equal(mac.Sum(nil), digest) {
			return nil
		}
	}
	if !usable {
		return fmt.Errorf("%w: no signing secret configured", ErrSignature)
	}
	return fmt.Errorf("%w: the signature does not match", ErrSignature)
}

// Event is one verified webhook delivery. Its concrete type is
// *IdentificationScoredEvent, *PingEvent or *UnknownEvent:
//
//	switch e := event.(type) {
//	case *webhook.IdentificationScoredEvent:
//		// e.Data is the scored identification
//	case *webhook.PingEvent:
//		// endpoint verification, nothing to do
//	case *webhook.UnknownEvent:
//		// an event type this version does not know; acknowledge it
//	}
type Event interface {
	// Type returns the event type, for example "identification.scored".
	Type() string
	isEvent()
}

// Envelope holds the fields every event has.
type Envelope struct {
	EventID string `json:"event_id,omitempty"`
	SiteID  int64  `json:"site_id,omitempty"`
	// EventType is the event type, for example "identification.scored".
	EventType string `json:"event_type"`
	// SchemaVersion is the event schema version, currently "2026-06-01".
	SchemaVersion string `json:"schema_version"`
	// CreatedAt is when the event was created (UTC), or the zero time when it
	// could not be read.
	CreatedAt time.Time `json:"created_at"`
	// Raw is the whole decoded body. Numbers are json.Number values.
	Raw map[string]any `json:"-"`
}

// Type returns the event type.
func (e *Envelope) Type() string { return e.EventType }

func (e *Envelope) isEvent() {}

// IdentificationScoredEvent is an identification.scored delivery. Make your
// handler idempotent on Data.RequestID.
type IdentificationScoredEvent struct {
	Envelope
	// Data is the scored identification. It is never nil.
	Data *shieldlabs.Identification `json:"data"`
}

// PingEvent is a webhook.ping delivery, sent when an endpoint is verified
// from the analytics dashboard. It has no data.
type PingEvent struct {
	Envelope
}

// UnknownEvent is a delivery with an event type this version does not know.
// Acknowledge it with a 2xx status; Raw holds the whole body.
type UnknownEvent struct {
	Envelope
}

// ConstructEvent verifies the signature of a delivery and parses it into a
// typed [Event]. Pass the raw request body, the X-Shield-Signature header
// value and one or more signing secrets.
//
// It returns an error matching [ErrSignature] when the signature is not
// valid (answer 401) and an error matching [ErrParse] when a correctly
// signed body is not a valid event (answer 400). Unknown event types and
// schema versions are not errors.
func ConstructEvent(payload []byte, header string, secrets ...string) (Event, error) {
	if err := verify(payload, header, secrets); err != nil {
		return nil, err
	}
	return parseEvent(payload)
}

func parseEvent(payload []byte) (Event, error) {
	raw, err := wire.DecodeObject(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	eventType, _ := raw["event_type"].(string)
	if eventType == "" {
		return nil, fmt.Errorf("%w: event_type is missing", ErrParse)
	}
	env := Envelope{EventType: eventType, Raw: raw}
	env.SchemaVersion, _ = raw["schema_version"].(string)
	env.EventID, _ = raw["event_id"].(string)
	_ = json.Unmarshal(fields["site_id"], &env.SiteID)
	if createdAt, ok := raw["created_at"].(string); ok {
		env.CreatedAt, _ = wire.ParseRFC3339(createdAt)
	}

	switch eventType {
	case EventTypeIdentificationScored:
		data, ok := fields["data"]
		if !ok || string(data) == "null" {
			return nil, fmt.Errorf("%w: %s event without data", ErrParse, EventTypeIdentificationScored)
		}
		ident, err := shieldlabs.ParseWebhookData(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParse, err)
		}
		return &IdentificationScoredEvent{Envelope: env, Data: ident}, nil
	case EventTypePing:
		return &PingEvent{Envelope: env}, nil
	}
	return &UnknownEvent{Envelope: env}, nil
}
