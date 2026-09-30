package webhook_test

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ShieldLabs-ai/shieldlabs-go/webhook"
)

func ExampleConstructEvent() {
	secret := os.Getenv("SHIELDLABS_WEBHOOK_SECRET") // whsec_...

	http.HandleFunc("POST /webhooks/shieldlabs", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "cannot read the body", http.StatusBadRequest)
			return
		}
		event, err := webhook.ConstructEvent(body, r.Header.Get(webhook.SignatureHeader), secret)
		if errors.Is(err, webhook.ErrSignature) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		if e, ok := event.(*webhook.IdentificationScoredEvent); ok {
			// Keep this idempotent on the request ID: a later server release
			// retries failed deliveries with identical bytes.
			log.Printf("request %s: risk score %d (%s)", e.Data.RequestID, e.Data.RiskScore, e.Data.Band())
		}
		w.WriteHeader(http.StatusOK) // acknowledge within one second
	})
}

func ExampleVerifySignature() {
	body := []byte(`{"created_at":"2026-09-30T12:34:56Z","event_type":"webhook.ping","schema_version":"2026-06-01"}`)
	header := "sha256=ea2685733d254f7028fb031c4214583b0650de01e6c8c93131236024edd9fdd8"

	// During a secret rotation, pass the new and the previous secret.
	ok := webhook.VerifySignature(body, header, "whsec_new_secret_value", "whsec_00112233445566778899aabbccddeeff")
	fmt.Println(ok)
	// Output:
	// true
}
