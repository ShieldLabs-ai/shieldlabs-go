package shieldlabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestUserListRejectsRepeatedIDsBeforeHTTP(t *testing.T) {
	for _, ids := range [][]string{{"first", "second"}, {"same", "same"}, {}, {""}} {
		srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) { t.Error("invalid ids reached HTTP") })
		c, _ := newTestClient(t, srv.URL)
		_, err := c.History.List(context.Background(), "user", &HistorySearchOptions{Query: url.Values{"ids": ids}})
		if err == nil || srv.Count() != 0 {
			t.Fatalf("ids=%v err=%v calls=%d", ids, err, srv.Count())
		}
	}
}

func TestUserListOneIDKeepsOtherFiltersRepeated(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if len(r.URL.Query()["ids"]) != 1 || r.URL.Query().Get("ids") != "a+b% c" {
			t.Error("ids changed")
		}
		if len(r.URL.Query()["risk_bands"]) != 2 {
			t.Error("bands stopped repeating")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "next_page_token": nil})
	})
	c, _ := newTestClient(t, srv.URL)
	_, err := c.History.List(context.Background(), "user", &HistorySearchOptions{Query: url.Values{"ids": {"a+b% c"}, "risk_bands": {"trusted", "dangerous"}}})
	if err != nil {
		t.Fatal(err)
	}
}
