package contract

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

func TestMissingFieldsStayMissingInEveryView(t *testing.T) {
	// Nil objects occur for missing/malformed nested data in older deliveries.
	// Every generated accessor must remain safe without strict decoding.
	views := []any{
		ReadHistoryRow(nil), ReadHistoryPage(nil), ReadDomainProfile(nil),
		ReadScoreDetail(nil), ReadIdentificationScoredData(nil), ReadDetectionFlags(nil),
		ReadIpInfo(nil), ReadTrafficSource(nil), ReadSignal(nil),
		ReadIdentificationScoredEvent(nil), ReadWebhookPingEvent(nil),
	}
	for _, view := range views {
		value := reflect.ValueOf(view)
		for i := 0; i < value.NumMethod(); i++ {
			result := value.Method(i).Call(nil)[0].FieldByName("Raw")
			if !result.IsNil() {
				t.Errorf("%T.%s changed a missing value", view, value.Type().Method(i).Name)
			}
		}
	}
}

func TestRawValuesAreNotCoerced(t *testing.T) {
	values := []any{nil, "future", json.Number("9007199254740993"), true, []any{}, map[string]any{"future": true}}
	for _, raw := range values {
		if got := ReadHistoryRow(map[string]any{"score": raw}).Score().Raw; !reflect.DeepEqual(got, raw) {
			t.Fatal(got)
		}
		if got := ReadDetectionFlags(map[string]any{"vpn": raw}).VPN().Raw; !reflect.DeepEqual(got, raw) {
			t.Fatal(got)
		}
		if got := ReadDomainProfile(map[string]any{"Weight": raw}).Weight().Raw; !reflect.DeepEqual(got, raw) {
			t.Fatal(got)
		}
		if got := ReadIdentificationScoredData(map[string]any{"risk_score": raw}).RiskScore().Raw; !reflect.DeepEqual(got, raw) {
			t.Fatal(got)
		}
		if got := ReadWebhookPingEvent(map[string]any{"event_type": raw}).EventType().Raw; !reflect.DeepEqual(got, raw) {
			t.Fatal(got)
		}
	}
}

func TestTolerantShapeHelpers(t *testing.T) {
	if Object(Value[IpInfo]{Raw: false}) != nil || Array(Value[[]Signal]{Raw: "malformed"}) != nil || String(Value[string]{Raw: 7}) != "" {
		t.Fatal("malformed values were coerced")
	}
	if Object(Value[IpInfo]{Raw: map[string]any{"ip": "future"}})["ip"] != "future" {
		t.Fatal("object lost")
	}
	if len(Array(Value[[]Signal]{Raw: []any{nil}})) != 1 || String(Value[string]{Raw: "future"}) != "future" {
		t.Fatal("values lost")
	}
}

func TestGeneratedRequestBuilders(t *testing.T) {
	request := SearchHistoryRequest{SearchType: SearchHistorySearchTypeUserHID, Value: "user", Limit: 2, Offset: 3}
	if request.Path(func(s string) string { return s }) != "/api/v1/history/user_hid/user" || request.Query().Get("limit") != "2" || request.Query().Get("offset") != "3" || len(request.Headers()) != 0 {
		t.Fatal("history request")
	}
	if !reflect.DeepEqual(request.Query(), url.Values{"limit": {"2"}, "offset": {"3"}}) {
		t.Fatal("history must not send unsupported optional parameters")
	}
	profile := GetDomainProfileRequest{XShieldDomain: "example.com"}
	if profile.Path(nil) != "/v1/profile" || profile.Headers().Get("X-Shield-Domain") != "example.com" || len(profile.Query()) != 0 {
		t.Fatal("profile request")
	}
	if !reflect.DeepEqual(profile.Headers(), url.Values{"X-Shield-Domain": {"example.com"}}) {
		t.Fatal("profile must not send unsupported optional parameters")
	}
}
