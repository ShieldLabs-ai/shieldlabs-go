package shieldlabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

const entityID = "33333333-3333-4333-8333-333333333333"

func entityCard(score any) map[string]any {
	return map[string]any{"id": entityID, "type": "identification", "created_at": "2026-10-29T09:00:00.123Z", "risk": map[string]any{"state": "ok", "score": score, "band": "suspicious"}, "signals": map[string]any{"state": "ok", "items": []any{"rate_limited", "vpn"}}, "public_ip": "203.0.113.24", "traffic": map[string]any{"channel": "paid", "utm_source": "google"}}
}
func TestGetCurrentEntityCard(t *testing.T) {
	for _, score := range []int{0, 30, 60, 100} {
		t.Run(strconv.Itoa(score), func(t *testing.T) {
			card := entityCard(score)
			srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": card})
			})
			c, _ := newTestClient(t, srv.URL)
			result, err := c.Identifications.Get(context.Background(), entityID, &GetIdentificationOptions{NoWait: true})
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.IdentificationID != entityID || result.RiskScore != score {
				t.Fatalf("result %#v", result)
			}
			if result.ObservedAt.Format("2006-01-02T15:04:05.000Z07:00") != "2026-10-29T09:00:00.123Z" {
				t.Fatal(result.ObservedAt)
			}
			if result.PublicIP.IP != "203.0.113.24" || result.TrafficSource.UTMSource != "google" {
				t.Fatalf("lost address/traffic: %#v", result)
			}
			if !*result.DetectionFlags.field("banned_ip") || !*result.DetectionFlags.field("vpn") || len(result.Signals) != 0 {
				t.Fatal("lost confirmed flags or fabricated weights")
			}
			if result.Raw["id"] != entityID {
				t.Fatal("lost raw card")
			}
		})
	}
}
func TestCurrentEntityListPreservesUnknownRiskAndCursor(t *testing.T) {
	card := entityCard(nil)
	card["type"] = "user"
	card["id"] = "a+b% c"
	card["risk"] = map[string]any{"state": "unavailable", "band": nil}
	card["related_counts"] = nil
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{card}, "next_page_token": "opaque+/="})
	})
	c, _ := newTestClient(t, srv.URL)
	first, err := c.History.List(context.Background(), "user", &HistorySearchOptions{Query: url.Values{"ids": {"a+b% c"}}})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextPageToken == nil || *first.NextPageToken != "opaque+/=" || len(first.Data) != 1 {
		t.Fatalf("page %#v", first)
	}
	risk := first.Data[0]["risk"].(map[string]any)
	if _, ok := risk["score"]; ok || first.Data[0]["related_counts"] != nil {
		t.Fatal("unknown values were fabricated")
	}
	if _, ok := reflect.TypeOf(*first).FieldByName("Total"); ok {
		t.Fatal("entity page must not invent total")
	}
	_, err = c.History.List(context.Background(), "user", &HistorySearchOptions{Query: url.Values{"ids": {"a+b% c"}, "page_token": {*first.NextPageToken}}})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Request(1).URL.Query().Get("page_token") != "opaque+/=" {
		t.Fatal("cursor changed")
	}
}
func TestCompatibilityEntityGetRejectsUnavailableScore(t *testing.T) {
	card := entityCard(nil)
	card["risk"] = map[string]any{"state": "unavailable"}
	body, _ := json.Marshal(map[string]any{"data": card})
	if _, err := parseHistoryPage(&apiResponse{status: 200, body: body}); err == nil {
		t.Fatal("unavailable became zero")
	}
}
func TestCurrentEntityPageRejectsMalformedResponses(t *testing.T) {
	for _, body := range []string{`{"data":{}}`, `{"data":[{}]}`, `{"data":[],"next_page_token":42}`} {
		if _, err := parseCurrentEntityPage(&apiResponse{status: 200, body: []byte(body)}); err == nil {
			t.Fatal(body)
		}
	}
}
