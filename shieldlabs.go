// Package shieldlabs is the ShieldLabs server SDK for Go: webhook verification,
// typed webhook events, and a History API client.
//
// Your code decides what to do with the score. This SDK never makes the decision
// for you.
package shieldlabs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WEBHOOK_SCHEMA_VERSION is the contract version emitted by Shield.Core.
const WEBHOOK_SCHEMA_VERSION = "2026-06-01"

const defaultBaseURL = "https://account.shieldlabs.ai/api"

// WebhookEvent is the POST body envelope.
type WebhookEvent struct {
	EventType     string             `json:"event_type"`
	SchemaVersion string             `json:"schema_version"`
	CreatedAt     time.Time          `json:"created_at"`
	Data          *WebhookScoredData `json:"data,omitempty"`
}

// WebhookScoredData is the payload inside identification.scored.
type WebhookScoredData struct {
	RequestID      string                `json:"request_id"`
	VisitorID      string                `json:"visitor_id"`
	DeviceID       string                `json:"device_id"`
	SessionID      string                `json:"session_id"`
	CookieID       string                `json:"cookie_id"`
	UserHID        *string               `json:"user_hid"`
	Domain         string                `json:"domain"`
	PublicIP       WebhookIPAddress      `json:"public_ip"`
	LocalIP        WebhookIPAddress      `json:"local_ip"`
	ConnectionType string                `json:"connection_type"`
	OS             string                `json:"os"`
	Browser        string                `json:"browser"`
	DeviceType     string                `json:"device_type"`
	TrafficSource  WebhookTrafficSource  `json:"traffic_source"`
	RiskScore      int                   `json:"risk_score"`
	Signals        []WebhookSignal       `json:"signals"`
	DetectionFlags WebhookDetectionFlags `json:"detection_flags"`
	ObservedAt     time.Time             `json:"observed_at"`
}

// WebhookIPAddress is an IP + country pair.
type WebhookIPAddress struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

// WebhookSignal is one scored signal.
type WebhookSignal struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
}

// WebhookTrafficSource is traffic attribution.
type WebhookTrafficSource struct {
	Channel        string `json:"channel"`
	ReferrerDomain string `json:"referrer_domain"`
	LandingURL     string `json:"landing_url"`
	ClickIDType    string `json:"click_id_type"`
	UTMSource      string `json:"utm_source"`
	UTMMedium      string `json:"utm_medium"`
	UTMCampaign    string `json:"utm_campaign"`
	UTMContent     string `json:"utm_content"`
	UTMTerm        string `json:"utm_term"`
}

// WebhookDetectionFlags matches Shield.Core entity.WebhookDetectionFlags.
type WebhookDetectionFlags struct {
	VPN                 bool `json:"vpn"`
	PrivacyRelay        bool `json:"privacy_relay"`
	BrowserVpnProxy     bool `json:"browser_vpn_proxy"`
	Tor                 bool `json:"tor"`
	Proxy               bool `json:"proxy"`
	DatacenterIP        bool `json:"datacenter_ip"`
	Abuser              bool `json:"abuser"`
	OSMismatch          bool `json:"os_mismatch"`
	OSNotDetected       bool `json:"os_not_detected"`
	TimezoneMismatch    bool `json:"timezone_mismatch"`
	AntiDetectBrowser   bool `json:"anti_detect_browser"`
	BrowserAutomation   bool `json:"browser_automation"`
	IPMismatch          bool `json:"ip_mismatch"`
	Incognito           bool `json:"incognito"`
	SearchBot           bool `json:"search_bot"`
	SuspiciousPaidClick bool `json:"suspicious_paid_click"`
	JavascriptDisabled  bool `json:"javascript_disabled"`
	StunNotChecked      bool `json:"stun_not_checked"`
}

// VerifyWebhook checks X-Shield-Signature against HMAC-SHA256(secret, payload).
// Comparison is constant-time. payload must be the raw request body bytes.
func VerifyWebhook(payload []byte, signature, secret string) bool {
	if signature == "" || secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Client talks to the History API on account.shieldlabs.ai.
type Client struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

// New returns a History API client.
func New(apiKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		BaseURL:    defaultBaseURL,
		HTTPClient: http.DefaultClient,
	}
}

// HistoryResponse is the {data, total} envelope from Portal.Admin.
type HistoryResponse struct {
	Data  []json.RawMessage `json:"data"`
	Total uint64            `json:"total"`
}

// GetHistory calls GET /api/v1/history/{searchType}/{value}.
func (c *Client) GetHistory(searchType, value string, limit, offset int) (*HistoryResponse, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/history/%s/%s", base, url.PathEscape(searchType), url.PathEscape(value)))
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shieldlabs history: status %d", resp.StatusCode)
	}
	var out HistoryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
