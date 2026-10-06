package shieldlabs

import (
	"encoding/json"
	"os"
	"testing"
)

func TestScopedClientIdentityParity(t *testing.T) {
	b, err := os.ReadFile("test-data-client-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture any
	json.Unmarshal(b, &fixture)
	h, _ := json.Marshal(map[string]any{"score": 70, "client_identity": fixture})
	w, _ := json.Marshal(map[string]any{"risk_score": 70, "client_identity": fixture})
	history, err := ParseHistoryRow(h)
	if err != nil {
		t.Fatal(err)
	}
	webhook, err := ParseWebhookData(w)
	if err != nil {
		t.Fatal(err)
	}
	if history.ClientIdentity == nil || webhook.ClientIdentity == nil || history.ClientIdentity.Verified[0].Subject != "provider" || history.ClientIdentity.Claims[0].AgentName != "GPTBot" || history.RiskScore != 70 || history.DetectionFlags.SearchBot {
		t.Fatal(history)
	}
	for _, raw := range []string{`{}`, `{"client_identity":null}`, `{"client_identity":{}}`} {
		id, err := ParseHistoryRow([]byte(raw))
		if err != nil || id.ClientIdentity != nil {
			t.Fatal(id, err)
		}
	}
	object := fixture.(map[string]any)
	object["availability"] = "future_state"
	object["extra"] = "kept"
	b, _ = json.Marshal(map[string]any{"client_identity": object})
	id, _ := ParseHistoryRow(b)
	if id.ClientIdentity.Availability != "future_state" || id.Raw["client_identity"].(map[string]any)["extra"] != "kept" {
		t.Fatal("future fields lost")
	}
}
