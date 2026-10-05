package webhook

import (
	"os"
	"testing"
)

func TestCurrentCoreFixturePreservesEventAndFP21(t *testing.T) {
	body, err := os.ReadFile("testdata/current.json")
	if err != nil {
		t.Fatal(err)
	}
	signature := sign("secret", body)
	e, err := ConstructEvent(body, signature, "secret")
	if err != nil {
		t.Fatal(err)
	}
	scored, ok := e.(*IdentificationScoredEvent)
	if !ok {
		t.Fatal("wrong type")
	}
	if scored.EventID == "" || scored.SiteID != 7 || len(scored.Data.RiskEvents) != 19 || scored.Data.Fingerprint == nil || scored.Data.Fingerprint.HardwareID != "sample-hardware" || scored.Data.HRE.AccountTakeover.Reason != "no_history" {
		t.Fatal("new contract lost", scored)
	}
}
