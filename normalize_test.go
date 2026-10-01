package shieldlabs

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

func TestNormalizationCases(t *testing.T) {
	cases := normalizationCases(t)
	sources := map[string]int{}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var (
				ident *Identification
				err   error
			)
			switch c.Source {
			case "history":
				ident, err = ParseHistoryRow(c.Input)
			case "webhook":
				ident, err = ParseWebhookData(c.Input)
			default:
				t.Fatalf("unknown source %q", c.Source)
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			assertMatchesFixture(t, c.Name, ident, c.Expected)

			// Raw keeps the original object, numbers included.
			wantRaw, err := wire.DecodeObject(c.Input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ident.Raw, wantRaw) {
				t.Errorf("Raw does not match the input object")
			}
			if string(ident.Source) != c.Source {
				t.Errorf("Source = %q, want %q", ident.Source, c.Source)
			}
		})
		sources[c.Source]++
	}
	if sources["history"] == 0 || sources["webhook"] == 0 {
		t.Fatalf("fixture must cover both sources, got %v", sources)
	}
}

func TestSignalSlugCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Description string `json:"description"`
			Slug        string `json:"slug"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "signal-slug-cases.json"), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		if got := SignalSlug(c.Description); got != c.Slug {
			t.Errorf("SignalSlug(%q) = %q, want %q", c.Description, got, c.Slug)
		}
	}
}

func TestSignalSlugExtraRules(t *testing.T) {
	tests := map[string]string{
		"≠":                         "neq",
		"İstanbul check":            "i̇stanbul_check",
		"a\t-b":                     "a_b",
		"Mixed/Case - Words":        "mixed_case_words",
		"\x1c Separator (x)":        "separator",
		"Sticky verdict:  Is VPN  ": "is_vpn",
		"Latency test":              "ws_tcp_latency",
		"Is tor ":                   "is_tor",
	}
	for in, want := range tests {
		if got := SignalSlug(in); got != want {
			t.Errorf("SignalSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRejectsNonObjects(t *testing.T) {
	for _, body := range []string{``, `[]`, `null`, `"x"`, `{"a":1} {}`, `{`} {
		if _, err := ParseHistoryRow([]byte(body)); err == nil {
			t.Errorf("ParseHistoryRow(%q): expected an error", body)
		}
		if _, err := ParseWebhookData([]byte(body)); err == nil {
			t.Errorf("ParseWebhookData(%q): expected an error", body)
		}
	}
}

func TestHistoryRowTolerance(t *testing.T) {
	row := `{
		"request_id": "7C1E2F4A-3B6D-4E8F-9A0B-1C2D3E4F5A6B",
		"score": 55.0,
		"score_details": "[1, {\"Value\": 12.5, \"Description\": \"Is VPN\"}, {\"Value\": true, \"Description\": \"Is tor\"}, {\"Value\": 30, \"Description\": 7}, {\"Value\": 5}]",
		"created_at": "  2026-09-30T08:00:00.123456789+02:00 ",
		"user_hid": 42,
		"is_vpn": "yes",
		"is_tor": 0,
		"is_proxy": [],
		"is_datacenter": {"a": 1},
		"connection_type": "satellite",
		"ip": " 0.0.0.0 ",
		"web_rtc_ip": "198.51.100.2",
		"webrtc_leak_source": " none ",
		"future_field": {"nested": true}
	}`
	ident, err := ParseHistoryRow([]byte(row))
	if err != nil {
		t.Fatal(err)
	}
	if ident.RiskScore != 55 {
		t.Errorf("RiskScore = %d, want 55", ident.RiskScore)
	}
	// Only integer, non-zero values become signals; an entry without a
	// description is slugged "unknown".
	want := []Signal{
		{Name: "unknown", Weight: 30, Description: ptr("")},
		{Name: "unknown", Weight: 5, Description: ptr("")},
	}
	if !reflect.DeepEqual(ident.Signals, want) {
		t.Errorf("Signals = %s, want %s", mustJSON(ident.Signals), mustJSON(want))
	}
	// A zone designator is ignored: History timestamps are UTC.
	if got := ident.ObservedAt.Format(time.RFC3339Nano); got != "2026-09-30T08:00:00.123456789Z" {
		t.Errorf("ObservedAt = %s", got)
	}
	if ident.UserHID == nil || *ident.UserHID != "42" {
		t.Errorf("UserHID = %v", ident.UserHID)
	}
	f := ident.DetectionFlags
	if !f.VPN || f.Tor || f.Proxy || !f.DatacenterIP {
		t.Errorf("truthiness of flag columns: %+v", f)
	}
	if ident.ConnectionType != "satellite" {
		t.Errorf("unknown connection types must be kept, got %q", ident.ConnectionType)
	}
	if ident.PublicIP.IP != "" || ident.LocalIP.IP != "198.51.100.2" {
		t.Errorf("IPs = %+v / %+v", ident.PublicIP, ident.LocalIP)
	}
	if ident.DetectionFlags.IPMismatch {
		t.Error("ip_mismatch needs both addresses")
	}
	if ident.RequestID != "7C1E2F4A-3B6D-4E8F-9A0B-1C2D3E4F5A6B" {
		t.Error("identifiers must be kept as received")
	}
}

func TestHistoryRowBadScoreDetails(t *testing.T) {
	for _, details := range []string{`""`, `"not json"`, `"{\"Value\": 5}"`, `"[] []"`, `null`, `[{"Value": 10, "Description": "Is VPN"}]`} {
		ident, err := ParseHistoryRow([]byte(`{"score_details": ` + details + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if ident.Signals == nil || len(ident.Signals) != 0 {
			t.Errorf("score_details %s: want an empty, non-nil list, got %#v", details, ident.Signals)
		}
	}
}

func TestHistoryIPMismatchRules(t *testing.T) {
	tests := []struct {
		row  string
		want bool
	}{
		{`{"ip":"203.0.113.1","web_rtc_ip":"198.51.100.1"}`, true},
		{`{"ip":"203.0.113.1","web_rtc_ip":"203.0.113.1"}`, false},
		{`{"ip":"203.0.113.1","web_rtc_ip":"0.0.0.0"}`, false},
		{`{"ip":"203.0.113.1","web_rtc_ip":"198.51.100.1","is_search_bot":true}`, false},
		{`{"ip":"203.0.113.1","web_rtc_ip":"203.0.113.1","score_details":"[{\"Value\":0,\"Description\":\"IP ≠ leakIP (x)\"}]"}`, true},
		{`{"ip":"203.0.113.1","webrtc_leak_source":"shield","webrtc_leak_ip":"198.51.100.9","web_rtc_ip":"203.0.113.1"}`, true},
		{`{"connection_type":"browser_vpn_proxy"}`, false},
	}
	for _, tc := range tests {
		ident, err := ParseHistoryRow([]byte(tc.row))
		if err != nil {
			t.Fatal(err)
		}
		if ident.DetectionFlags.IPMismatch != tc.want {
			t.Errorf("%s: ip_mismatch = %v, want %v", tc.row, ident.DetectionFlags.IPMismatch, tc.want)
		}
	}
	ident, _ := ParseHistoryRow([]byte(`{"connection_type":"browser_vpn_proxy"}`))
	if !ident.DetectionFlags.BrowserVPNProxy {
		t.Error("browser_vpn_proxy is derived from connection_type")
	}
}

func TestWebhookDataTolerance(t *testing.T) {
	data := `{
		"user_hid": "",
		"public_ip": {"ip": "0.0.0.0", "country": null},
		"local_ip": "not an object",
		"traffic_source": {"channel": null, "utm_term": "spring"},
		"signals": [{"name": "vpn", "weight": 15}, "junk", {"weight": 2.9}],
		"detection_flags": {"vpn": true, "future_flag": true},
		"risk_score": 999,
		"observed_at": "2026-09-30T12:34:57.482913041+01:30"
	}`
	ident, err := ParseWebhookData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if ident.UserHID != nil {
		t.Error("an empty user_hid becomes nil")
	}
	if ident.PublicIP != (IPInfo{}) || ident.LocalIP != (IPInfo{}) {
		t.Errorf("IPs = %+v / %+v", ident.PublicIP, ident.LocalIP)
	}
	if ident.TrafficSource.Channel != "" || ident.TrafficSource.UTMTerm != "spring" {
		t.Errorf("TrafficSource = %+v", ident.TrafficSource)
	}
	want := []Signal{{Name: "vpn", Weight: 15}, {Name: "", Weight: 2}}
	if !reflect.DeepEqual(ident.Signals, want) {
		t.Errorf("Signals = %s", mustJSON(ident.Signals))
	}
	if !ident.DetectionFlags.VPN || ident.DetectionFlags.Tor {
		t.Errorf("flags = %+v", ident.DetectionFlags)
	}
	if got := ident.ObservedAt.Format(time.RFC3339Nano); got != "2026-09-30T11:04:57.482913041Z" {
		t.Errorf("ObservedAt = %s", got)
	}
	if !ident.IsRateLimited() || ident.Band() != BandRateLimited {
		t.Error("999 is the rate-limit marker")
	}

	empty, err := ParseWebhookData([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Signals == nil || !empty.ObservedAt.IsZero() || empty.Source != SourceWebhook {
		t.Errorf("empty data: %+v", empty)
	}
}

func TestDetectionFlagsAccessors(t *testing.T) {
	names := DetectionFlagNames()
	if len(names) != 19 {
		t.Fatalf("want 19 flag names, got %d", len(names))
	}
	names[0] = "changed"
	if DetectionFlagNames()[0] != FlagVPN {
		t.Error("DetectionFlagNames must return a copy")
	}
	var f DetectionFlags
	for i, name := range DetectionFlagNames() {
		*f.field(name) = i%2 == 0
	}
	m := f.Map()
	if len(m) != 19 {
		t.Fatalf("Map has %d entries", len(m))
	}
	for i, name := range DetectionFlagNames() {
		v, ok := f.Get(name)
		if !ok || v != (i%2 == 0) || m[name] != v {
			t.Errorf("flag %s: Get = %v, %v; Map = %v", name, v, ok, m[name])
		}
	}
	if _, ok := f.Get("not_a_flag"); ok {
		t.Error("unknown names must report ok = false")
	}
	// JSON names match the wire names.
	b, _ := json.Marshal(f)
	var decoded map[string]bool
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, m) {
		t.Errorf("JSON encoding does not match the wire names:\n%s", b)
	}
}

func TestValueHelpers(t *testing.T) {
	if !truthy(json.Number("1e999")) || truthy(json.Number("0.0")) || !truthy(1.5) || truthy(0.0) || !truthy(struct{}{}) {
		t.Error("truthy numbers")
	}
	if toInt64(json.Number("1e2")) != 100 || toInt64(json.Number("-7")) != -7 || toInt64(json.Number("1e400")) != 0 ||
		toInt64(3.9) != 3 || toInt64("12") != 0 || toInt64(nil) != 0 {
		t.Error("toInt64")
	}
	if str(json.Number("5")) != "5" || str(true) != "" || str(nil) != "" {
		t.Error("str")
	}
}

func ptr[T any](v T) *T { return &v }
