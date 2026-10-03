package shieldlabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/contract"
)

func TestGeneratedContractCoverage(t *testing.T) {
	flags := webhookFlags(contract.ReadDetectionFlags(nil))
	if len(flags) != contract.DetectionFlagsFieldCount || len(flags) != len(flagNames) {
		t.Fatal("generated flag coverage must match normalization")
	}
	for _, name := range flagNames {
		if _, ok := flags[name]; !ok {
			t.Errorf("missing generated flag %s", name)
		}
	}
	for _, lookup := range contract.SearchHistorySearchTypeValues() {
		value := NilUUID
		if lookup == "ip" {
			value = "192.0.2.1"
		}
		if _, err := validateLookup(LookupType(lookup), value); err != nil {
			t.Errorf("generated lookup coverage: %s: %v", lookup, err)
		}
	}
}

func TestGeneratedViewsKeepMalformedAndFutureData(t *testing.T) {
	ident, err := ParseHistoryRow([]byte(`{"request_id":123,"score":12.9,"connection_type":"future-network","is_vpn":"yes","user_hid":null,"future_diagnostic":{"n":9007199254740993}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ident.RequestID != "123" || ident.RiskScore != 12 || !ident.DetectionFlags.VPN || ident.UserHID != nil || string(ident.ConnectionType) != "future-network" {
		t.Fatalf("tolerant history normalization changed: %+v", ident)
	}
	if got := ident.Raw["future_diagnostic"].(map[string]any)["n"]; got != json.Number("9007199254740993") {
		t.Fatal(got)
	}
	data, err := ParseWebhookData([]byte(`{"risk_score":"12","connection_type":"future-network","detection_flags":{"vpn":"yes","future_flag":true},"traffic_source":[],"signals":[null,{"name":7,"weight":-2.5}],"public_ip":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if data.RiskScore != 0 || !data.DetectionFlags.VPN || data.PublicIP.IP != "" || data.TrafficSource.Channel != "" || len(data.Signals) != 1 || data.Signals[0].Name != "7" || data.Signals[0].Weight != -2 {
		t.Fatalf("tolerant webhook normalization changed: %+v", data)
	}
	if !reflect.DeepEqual(data.Raw["traffic_source"], []any{}) {
		t.Fatal("raw malformed traffic source lost")
	}
}

func TestGeneratedProfileViewsOnHTTPResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profile" || r.Header.Get("X-Shield-Domain") != "example.com" {
			t.Error("wrong generated request")
		}
		_, _ = w.Write([]byte(`{"Domain":123,"Weight":-2.5,"PublicKey":null,"Secret":[],"CreatedAt":false,"future":{"value":9007199254740993}}`))
	}))
	defer server.Close()
	client, err := NewManagementClient("fixture", "example.com", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := client.GetProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if profile.Domain != "123" || profile.RemainingIdentifications != -2 || profile.PublicKeyMasked != "" || profile.SecretKeyMasked != "" || !profile.CreatedAt.IsZero() {
		t.Fatalf("%+v", profile)
	}
	if got := profile.Raw["future"].(map[string]any)["value"]; got != json.Number("9007199254740993") {
		t.Fatal(got)
	}
}
