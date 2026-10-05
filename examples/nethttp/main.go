// Command nethttp is a minimal net/http server that shows both halves of a
// ShieldLabs integration:
//
//   - POST /signup reads the request ID that the browser agent returned,
//     waits for its verdict with the History API and applies a guard policy
//     before creating the account.
//   - POST /webhooks/shieldlabs verifies webhook deliveries and logs them.
//
// Run it from the repository root:
//
//	SHIELDLABS_API_KEY=sec_your_private_key \
//	SHIELDLABS_WEBHOOK_SECRET=whsec_your_signing_secret \
//	go run ./examples/nethttp -addr 127.0.0.1:8080
//
// Then post a request ID from your page:
//
//	curl -X POST http://127.0.0.1:8080/signup \
//	  -H 'Content-Type: application/json' \
//	  -d '{"requestId":"3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"}'
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
	"github.com/ShieldLabs-ai/shieldlabs-go/webhook"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	flag.Parse()

	client, err := shieldlabs.NewClient(os.Getenv("SHIELDLABS_API_KEY"),
		// Optional override for development and tests; empty keeps the default.
		shieldlabs.WithBaseURL(os.Getenv("SHIELDLABS_API_BASE_URL")))
	if err != nil {
		log.Fatalf("configure the ShieldLabs client: %v", err)
	}
	secret := os.Getenv("SHIELDLABS_WEBHOOK_SECRET")
	if secret == "" {
		log.Print("SHIELDLABS_WEBHOOK_SECRET is not set: every webhook delivery will be rejected")
	}

	a := newApp(client, []string{secret}, 10*time.Second)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listening on http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

// app holds the handlers and their state.
type app struct {
	client         *shieldlabs.Client
	webhookSecrets []string
	waitTimeout    time.Duration

	// usedRequestIDs makes one identification authorize one signup attempt.
	usedRequestIDs *recentSet
	// deliveries is demo-only in-memory dedup by event ID (legacy: request ID).
	// Production needs a durable inbox before 2xx; retries resend identical bytes.
	deliveries *recentSet
}

func newApp(client *shieldlabs.Client, webhookSecrets []string, waitTimeout time.Duration) *app {
	return &app{
		client:         client,
		webhookSecrets: webhookSecrets,
		waitTimeout:    waitTimeout,
		usedRequestIDs: newRecentSet(10 * time.Minute),
		deliveries:     newRecentSet(24 * time.Hour),
	}
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup", a.signup)
	mux.HandleFunc("POST /webhooks/shieldlabs", a.webhook)
	return mux
}

// signup guards account creation with the identification the browser agent
// created for this submission.
func (a *app) signup(w http.ResponseWriter, r *http.Request) {
	requestID := readRequestID(w, r)
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "requestId is required"})
		return
	}

	// Scoring is asynchronous: wait for the verdict, with waitTimeout as the
	// total budget.
	ident, err := a.client.Identifications.Get(r.Context(), requestID,
		&shieldlabs.GetIdentificationOptions{Timeout: a.waitTimeout})
	switch {
	case errors.Is(err, shieldlabs.ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "requestId is not a valid request ID"})
		return
	case err != nil:
		// The verdict could not be read. An unverified request is never
		// treated as clean: refuse it, or queue it for review.
		log.Printf("signup: reading the identification failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "reason": "unverified"})
		return
	}

	// The default policy refuses a missing identification, a reused or stale
	// one, the rate-limit marker, a nil device ID, the browser_automation and
	// javascript_disabled flags, and the dangerous band.
	verdict := shieldlabs.EvaluateIdentification(ident, shieldlabs.EvaluateOptions{
		IsReplay: a.usedRequestIDs.seenBefore,
	})
	if !verdict.OK {
		log.Printf("signup refused: request %s, reason %s, band %q, flag %q", requestID, verdict.Reason, verdict.Band, verdict.Flag)
		// The reason is returned for the demo; production code usually
		// shows a generic message instead.
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "reason": verdict.Reason})
		return
	}

	// Create the account here. The identifiers support account-abuse checks,
	// for example counting the accounts of ident.DeviceID with
	// a.client.History.Search(ctx, shieldlabs.LookupDeviceID, ident.DeviceID, nil)
	// and Identification.AccountUserHID, which skips "anonymous" and the other
	// User HID values that name no account.
	log.Printf("signup accepted: request %s, risk score %d (%s)", requestID, ident.RiskScore, verdict.Band)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webhook verifies a delivery, acknowledges it quickly and logs it.
func (a *app) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read the body", http.StatusBadRequest)
		return
	}
	event, err := webhook.ConstructEvent(body, r.Header.Get(webhook.SignatureHeader), a.webhookSecrets...)
	switch {
	case errors.Is(err, webhook.ErrSignature):
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	case err != nil:
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	switch e := event.(type) {
	case *webhook.IdentificationScoredEvent:
		deliveryID:=e.EventID; if deliveryID=="" {deliveryID=e.Data.RequestID}
		if a.deliveries.seenBefore(deliveryID) {
			log.Printf("webhook: request %s already handled", e.Data.RequestID)
			break
		}
		log.Printf("webhook: request %s scored %d (%s), device %s, flags automation=%v vpn=%v",
			e.Data.RequestID, e.Data.RiskScore, e.Data.Band(), e.Data.DeviceID,
			e.Data.DetectionFlags.BrowserAutomation, e.Data.DetectionFlags.VPN)
	case *webhook.PingEvent:
		log.Print("webhook: ping received")
	default:
		log.Printf("webhook: ignoring event type %q", event.Type())
	}
	w.WriteHeader(http.StatusOK)
}

// readRequestID accepts a JSON body {"requestId": "..."} or a form field
// named requestId.
func readRequestID(w http.ResponseWriter, r *http.Request) string {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			RequestID string `json:"requestId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return ""
		}
		return strings.TrimSpace(body.RequestID)
	}
	return strings.TrimSpace(r.FormValue("requestId"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// recentSet remembers keys for a limited time. It stands in for a shared
// store (a database table or a cache with expiry) that all your servers use.
type recentSet struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func newRecentSet(ttl time.Duration) *recentSet {
	return &recentSet{ttl: ttl, seen: make(map[string]time.Time)}
}

// seenBefore records key and reports whether it had been recorded already.
// The check and the write happen atomically.
func (s *recentSet) seenBefore(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, at := range s.seen {
		if now.Sub(at) > s.ttl {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[key]; ok {
		return true
	}
	s.seen[key] = now
	return false
}
