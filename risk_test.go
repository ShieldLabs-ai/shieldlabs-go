package shieldlabs

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRiskBandCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Score int    `json:"score"`
			Band  string `json:"band"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "risk-band-cases.json"), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		if got := RiskBand(c.Score); string(got) != c.Band {
			t.Errorf("RiskBand(%d) = %s, want %s", c.Score, got, c.Band)
		}
		if got := IsRateLimited(c.Score); got != (c.Band == "rate_limited") {
			t.Errorf("IsRateLimited(%d) = %v", c.Score, got)
		}
		ident := &Identification{RiskScore: c.Score}
		if string(ident.Band()) != c.Band || ident.IsRateLimited() != (c.Band == "rate_limited") {
			t.Errorf("Identification methods disagree for %d", c.Score)
		}
	}
	if RiskBand(-5) != BandTrusted || RiskBand(101) != BandRateLimited || IsRateLimited(100) {
		t.Error("boundaries")
	}
}

func freshIdentification(now time.Time) *Identification {
	return &Identification{
		RequestID:  testRequestID,
		DeviceID:   "d8e0f2a4-b6c8-4d0e-bf2a-4b6c8d0e2f4a",
		RiskScore:  10,
		ObservedAt: now.Add(-30 * time.Second),
		Source:     SourceHistory,
	}
}

func TestEvaluateIdentificationDefaults(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	opts := EvaluateOptions{Now: now}

	tests := []struct {
		name   string
		mutate func(*Identification)
		want   Evaluation
	}{
		{"ok", func(*Identification) {}, Evaluation{OK: true, Band: BandTrusted}},
		{"suspicious passes by default", func(i *Identification) { i.RiskScore = 45 }, Evaluation{OK: true, Band: BandSuspicious}},
		{"stale", func(i *Identification) { i.ObservedAt = now.Add(-6 * time.Minute) }, Evaluation{Reason: ReasonStale, Band: BandTrusted}},
		{"unknown time is stale", func(i *Identification) { i.ObservedAt = time.Time{} }, Evaluation{Reason: ReasonStale, Band: BandTrusted}},
		{"future time is fresh", func(i *Identification) { i.ObservedAt = now.Add(time.Minute) }, Evaluation{OK: true, Band: BandTrusted}},
		{"rate limited", func(i *Identification) { i.RiskScore = 999 }, Evaluation{Reason: ReasonRateLimited, Band: BandRateLimited}},
		{"no device signals", func(i *Identification) { i.DeviceID = NilUUID }, Evaluation{Reason: ReasonNoDeviceSignals, Band: BandTrusted}},
		{"automation", func(i *Identification) { i.DetectionFlags.BrowserAutomation = true }, Evaluation{Reason: ReasonBlockedFlag, Band: BandTrusted, Flag: FlagBrowserAutomation}},
		{"javascript disabled", func(i *Identification) { i.DetectionFlags.JavaScriptDisabled = true; i.RiskScore = 90 }, Evaluation{Reason: ReasonBlockedFlag, Band: BandDangerous, Flag: FlagJavaScriptDisabled}},
		{"vpn alone passes", func(i *Identification) { i.DetectionFlags.VPN = true }, Evaluation{OK: true, Band: BandTrusted}},
		{"dangerous", func(i *Identification) { i.RiskScore = 80 }, Evaluation{Reason: ReasonBlockedBand, Band: BandDangerous}},
		{"stale before rate limited", func(i *Identification) { i.RiskScore = 999; i.ObservedAt = now.Add(-time.Hour) }, Evaluation{Reason: ReasonStale, Band: BandRateLimited}},
		{"rate limited before nil device", func(i *Identification) { i.RiskScore = 999; i.DeviceID = NilUUID }, Evaluation{Reason: ReasonRateLimited, Band: BandRateLimited}},
		{"nil device before flags", func(i *Identification) { i.DeviceID = NilUUID; i.DetectionFlags.BrowserAutomation = true }, Evaluation{Reason: ReasonNoDeviceSignals, Band: BandTrusted}},
		{"flags before band", func(i *Identification) { i.RiskScore = 80; i.DetectionFlags.BrowserAutomation = true }, Evaluation{Reason: ReasonBlockedFlag, Band: BandDangerous, Flag: FlagBrowserAutomation}},
	}
	for _, tc := range tests {
		ident := freshIdentification(now)
		tc.mutate(ident)
		if got := EvaluateIdentification(ident, opts); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestEvaluateIdentificationMissingAndReplay(t *testing.T) {
	calls := 0
	isReplay := func(id string) bool {
		calls++
		return id == testRequestID
	}
	if got := EvaluateIdentification(nil, EvaluateOptions{IsReplay: isReplay}); got != (Evaluation{Reason: ReasonMissing}) {
		t.Errorf("missing: %+v", got)
	}
	if calls != 0 {
		t.Error("IsReplay must not run for a missing identification")
	}
	now := time.Now()
	stale := freshIdentification(now)
	stale.ObservedAt = now.Add(-time.Hour)
	if got := EvaluateIdentification(stale, EvaluateOptions{IsReplay: isReplay}); got.Reason != ReasonReplayed || got.OK {
		t.Errorf("replay is checked before freshness: %+v", got)
	}
	other := freshIdentification(now)
	other.RequestID = "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"
	if got := EvaluateIdentification(other, EvaluateOptions{IsReplay: isReplay}); !got.OK {
		t.Errorf("a new request ID with the real clock: %+v", got)
	}
	if calls != 2 {
		t.Errorf("IsReplay calls = %d", calls)
	}
}

func TestEvaluateIdentificationCustomOptions(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ident := freshIdentification(now)
	ident.ObservedAt = now.Add(-time.Hour)
	ident.RiskScore = 45
	ident.DetectionFlags.VPN = true
	ident.DetectionFlags.BrowserAutomation = true

	got := EvaluateIdentification(ident, EvaluateOptions{Now: now, MaxAge: -1, BlockFlags: []string{"not_a_flag", FlagVPN}})
	if got != (Evaluation{Reason: ReasonBlockedFlag, Band: BandSuspicious, Flag: FlagVPN}) {
		t.Errorf("custom flags: %+v", got)
	}
	got = EvaluateIdentification(ident, EvaluateOptions{Now: now, MaxAge: 2 * time.Hour, BlockFlags: []string{}, BlockBands: []Band{BandSuspicious, BandDangerous}})
	if got != (Evaluation{Reason: ReasonBlockedBand, Band: BandSuspicious}) {
		t.Errorf("custom bands: %+v", got)
	}
	ident.RiskScore = 85
	got = EvaluateIdentification(ident, EvaluateOptions{Now: now, MaxAge: -1, BlockFlags: []string{}, BlockBands: []Band{}})
	if !got.OK || got.Band != BandDangerous {
		t.Errorf("empty lists block nothing: %+v", got)
	}
	b, _ := json.Marshal(Evaluation{Reason: ReasonBlockedFlag, Band: BandTrusted, Flag: FlagVPN})
	if string(b) != `{"ok":false,"reason":"blocked_flag","band":"trusted","flag":"vpn"}` {
		t.Errorf("JSON = %s", b)
	}
}

func TestUserHID(t *testing.T) {
	// Expected values computed independently with HMAC-SHA256.
	got, err := UserHID("user-42", "server-side-secret")
	if err != nil || got != "7900fe533a0c4a3231be8bf94641b2f0b20bd2af0ef7bf2eadb759233cc3d822" {
		t.Errorf("UserHID = %q, %v", got, err)
	}
	got, err = UserHID("usér@example.com", "clé")
	if err != nil || got != "0dfa853f79feb940dab1a60aaec4bd3df624f8b6534a1f5b743bcd685278de59" {
		t.Errorf("UserHID (UTF-8) = %q, %v", got, err)
	}
	if _, err := UserHID("", "secret"); !errors.Is(err, ErrValidation) {
		t.Errorf("empty user ID: %v", err)
	}
	if _, err := UserHID("user-42", ""); !errors.Is(err, ErrValidation) {
		t.Errorf("empty secret: %v", err)
	}
}
