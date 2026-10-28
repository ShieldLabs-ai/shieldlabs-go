package shieldlabs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEntityListOmitsIncludeTotal(t *testing.T) {
	const domain = "00000000-0000-4000-8000-000000000031"
	body := `{"data":[{"type":"user","id":"customer-42","domain_id":"` + domain + `","domain":"example.com","risk":{"state":"unavailable","band":null,"as_of":null},"signals":{"state":"ok","items":[]}}],"next_page_token":null}`
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		if !strings.HasPrefix(r.URL.Path, "/api/v1/domains/"+domain+"/history/user") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	client, err := NewClient(testAPIKey, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Entities.List(context.Background(), domain, "user", &EntityListOptions{
		Filter: map[string]any{"identification": map[string]any{"risk_bands": []any{"dangerous"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 1 || page.NextPageToken != nil {
		t.Fatalf("page = %#v", page)
	}
	if strings.Contains(query, "include_total") {
		t.Fatalf("query sent include_total: %s", query)
	}
	if !strings.Contains(query, "limit=20") || !strings.Contains(query, "risk_bands") {
		t.Fatalf("query = %s", query)
	}
}

func TestEntityIncludeTotalHasNoField(t *testing.T) {
	client, err := NewClient(testAPIKey, WithBaseURL("https://account.shieldlabs.ai"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Entities.List(context.Background(), "not-a-uuid", "visitor", nil)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}

func TestEntityGetCard(t *testing.T) {
	const domain = "00000000-0000-4000-8000-000000000031"
	body := `{"data":{"type":"user","id":"customer-42","domain_id":"` + domain + `","domain":"example.com","risk":{"state":"unavailable","band":null,"as_of":null},"signals":{"state":"ok","items":[]}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/"+domain+"/history/user/customer-42" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	client, err := NewClient(testAPIKey, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	card, err := client.Entities.Get(context.Background(), domain, "user", "customer-42", nil)
	if err != nil {
		t.Fatal(err)
	}
	if card["id"] != "customer-42" {
		t.Fatalf("card = %#v", card)
	}
}

func TestEntityMalformedRiskIsRejected(t *testing.T) {
	const domain = "00000000-0000-4000-8000-000000000031"
	body := `{"data":[{"type":"user","id":"customer-42","domain_id":"` + domain + `","domain":"example.com","risk":{"state":"ok","band":"dangerous"},"signals":{"state":"ok","items":[]}}],"next_page_token":null}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	client, err := NewClient(testAPIKey, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Entities.List(context.Background(), domain, "user", nil)
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("err = %v", err)
	}
}
