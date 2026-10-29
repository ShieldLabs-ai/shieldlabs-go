package shieldlabs

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// EntityPage preserves current entity cards and the opaque cursor. It has no total.
type EntityPage struct {
	Data          []map[string]any `json:"data"`
	NextPageToken *string          `json:"next_page_token"`
}

func parseCurrentEntityPage(resp *apiResponse) (*EntityPage, error) {
	body, err := wire.DecodeObject(resp.body)
	invalid := func() error {
		return &APIError{StatusCode: resp.status, Message: "History returned an invalid entity page", Body: resp.body, Header: resp.header}
	}
	if err != nil {
		return nil, invalid()
	}
	rows, ok := body["data"].([]any)
	if !ok {
		return nil, invalid()
	}
	page := &EntityPage{Data: []map[string]any{}}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, invalid()
		}
		if _, ok := row["id"].(string); !ok {
			return nil, invalid()
		}
		if _, ok := row["type"].(string); !ok {
			return nil, invalid()
		}
		if _, ok := row["risk"].(map[string]any); !ok {
			return nil, invalid()
		}
		page.Data = append(page.Data, row)
	}
	if token := body["next_page_token"]; token != nil {
		value, ok := token.(string)
		if !ok {
			return nil, invalid()
		}
		page.NextPageToken = &value
	}
	return page, nil
}

func identificationFromEntityOrRow(row map[string]any) (*Identification, error) {
	risk, _ := row["risk"].(map[string]any)
	if _, ok := row["type"].(string); !ok {
		return identificationFromHistoryRow(row), nil
	}
	score, err := 0, strconv.ErrSyntax
	switch number := risk["score"].(type) {
	case json.Number:
		score, err = strconv.Atoi(string(number))
	case int:
		score, err = number, nil
	}
	if risk["state"] != "ok" || err != nil || score < 0 || score > 100 {
		return nil, &APIError{StatusCode: 200, Message: "Risk Score is unavailable or invalid in this entity card; entity lists preserve its availability state"}
	}
	legacy := make(map[string]any, len(row))
	for key, value := range row {
		legacy[key] = value
	}
	legacy["identification_id"], legacy["score"] = row["id"], json.Number(strconv.Itoa(score))
	legacy["ip"], legacy["web_rtc_ip"], legacy["web_rtc_country"] = row["public_ip"], row["local_ip"], row["local_country"]
	if traffic, ok := row["traffic"].(map[string]any); ok {
		for _, key := range []string{"referrer_domain", "entry_url", "click_id_type", "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"} {
			legacy[key] = traffic[key]
		}
		legacy["traffic_channel"] = traffic["channel"]
	}
	result := identificationFromHistoryRow(legacy)
	if observed, err := time.Parse(time.RFC3339Nano, str(row["created_at"])); err == nil {
		result.ObservedAt = observed.UTC()
	}
	names := map[string]bool{}
	if signals, ok := row["signals"].(map[string]any); ok && signals["state"] == "ok" {
		if items, ok := signals["items"].([]any); ok {
			for _, item := range items {
				if name, ok := item.(string); ok {
					names[name] = true
				}
			}
		}
	}
	aliases := map[string]string{"banned_ip": "rate_limited", "private_relay": "privacy_relay", "network_check_incomplete": "stun_not_checked", "latency_test": "ws_tcp_latency"}
	for _, key := range flagNames {
		*result.DetectionFlags.field(key) = names[key] || names[aliases[key]]
	}
	result.Raw = row
	return result, nil
}
