package shieldlabs

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// historyFlagColumns maps a detection flag to its History row column. The
// browser_vpn_proxy and ip_mismatch flags have no column and are derived.
var historyFlagColumns = map[string]string{
	FlagVPN:                 "is_vpn",
	FlagPrivacyRelay:        "is_privacy_relay",
	FlagTor:                 "is_tor",
	FlagProxy:               "is_proxy",
	FlagDatacenterIP:        "is_datacenter",
	FlagAbuser:              "is_abuser",
	FlagOSMismatch:          "is_os_mismatch",
	FlagOSNotDetected:       "is_os_not_detected",
	FlagTimezoneMismatch:    "is_timezone_mismatch",
	FlagAntiDetectBrowser:   "is_antidetect",
	FlagBrowserAutomation:   "is_browser_automation",
	FlagIncognito:           "is_incognito",
	FlagSearchBot:           "is_search_bot",
	FlagSuspiciousPaidClick: "is_suspicious_paid_click",
	FlagJavaScriptDisabled:  "is_js_disabled",
	FlagStunNotChecked:      "is_stun_not_checked",
	FlagCheckIncomplete:     "check_incomplete",
}

// ipLeakPrefix starts the History description that reports a difference
// between the public and the local IP address.
const ipLeakPrefix = "IP ≠ leakIP"

// ParseHistoryRow normalizes one row of a History API response (a JSON
// object) into an [Identification]. The History client already does this
// for you; the function is exported for rows obtained another way.
func ParseHistoryRow(row []byte) (*Identification, error) {
	m, err := wire.DecodeObject(row)
	if err != nil {
		return nil, fmt.Errorf("shieldlabs: cannot parse History row: %w", err)
	}
	return identificationFromHistoryRow(m), nil
}

// ParseWebhookData normalizes the data object of an identification.scored
// webhook event into an [Identification]. It does not verify a signature:
// use the webhook package to verify and parse a delivery in one step.
func ParseWebhookData(data []byte) (*Identification, error) {
	m, err := wire.DecodeObject(data)
	if err != nil {
		return nil, fmt.Errorf("shieldlabs: cannot parse webhook data: %w", err)
	}
	return identificationFromWebhookData(m), nil
}

func identificationFromHistoryRow(row map[string]any) *Identification {
	var localIP, localCountry string
	if src := wire.Strip(str(row["webrtc_leak_source"])); src != "" && src != "none" {
		localIP, localCountry = normalizeIP(str(row["webrtc_leak_ip"])), str(row["webrtc_leak_country"])
	} else {
		localIP, localCountry = normalizeIP(str(row["web_rtc_ip"])), str(row["web_rtc_country"])
	}
	publicIP := normalizeIP(str(row["ip"]))

	signals, ipLeakDetail := historySignals(row["score_details"])

	var flags DetectionFlags
	searchBot := truthy(row["is_search_bot"])
	for _, name := range flagNames {
		var v bool
		switch name {
		case FlagBrowserVPNProxy:
			v = row["connection_type"] == "browser_vpn_proxy"
		case FlagIPMismatch:
			v = !searchBot && (ipLeakDetail || (publicIP != "" && localIP != "" && publicIP != localIP))
		default:
			v = truthy(row[historyFlagColumns[name]])
		}
		*flags.field(name) = v
	}

	domain := str(row["site_domain"])
	if domain == "" {
		domain = str(row["domain"])
	}
	observedAt, _ := wire.ParseHistoryTime(str(row["created_at"]))

	return &Identification{
		RequestID:      str(row["request_id"]),
		VisitorID:      str(row["visitor_id"]),
		DeviceID:       str(row["device_id"]),
		SessionID:      str(row["session_id"]),
		CookieID:       str(row["cookie_id"]),
		UserHID:        nullableString(row["user_hid"]),
		Domain:         domain,
		PublicIP:       IPInfo{IP: publicIP, Country: str(row["country"])},
		LocalIP:        IPInfo{IP: localIP, Country: localCountry},
		ConnectionType: ConnectionType(str(row["connection_type"])),
		OS:             str(row["os"]),
		Browser:        str(row["browser"]),
		DeviceType:     str(row["device_type"]),
		TrafficSource: TrafficSource{
			Channel:        str(row["traffic_channel"]),
			ReferrerDomain: str(row["referrer_domain"]),
			LandingURL:     str(row["entry_url"]),
			ClickIDType:    str(row["click_id_type"]),
			UTMSource:      str(row["utm_source"]),
			UTMMedium:      str(row["utm_medium"]),
			UTMCampaign:    str(row["utm_campaign"]),
			UTMContent:     str(row["utm_content"]),
			UTMTerm:        str(row["utm_term"]),
		},
		RiskScore:      toInt(row["score"]),
		Signals:        signals,
		DetectionFlags: flags,
		ObservedAt:     observedAt,
		Source:         SourceHistory,
		Raw:            row,
		ClientIdentity: parseClientIdentity(row["client_identity"]),
	}
}

// historySignals parses the score_details JSON string of a History row. It
// keeps the entries with a non-zero integer Value, in order, and reports
// whether an IP leak description was present (at any weight).
func historySignals(scoreDetails any) ([]Signal, bool) {
	signals := []Signal{}
	text, _ := scoreDetails.(string)
	if text == "" {
		return signals, false
	}
	v, err := wire.Decode([]byte(text))
	if err != nil {
		return signals, false
	}
	details, ok := v.([]any)
	if !ok {
		return signals, false
	}
	ipLeak := false
	for _, item := range details {
		d, ok := item.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := d["Description"].(string)
		if strings.HasPrefix(desc, ipLeakPrefix) {
			ipLeak = true
		}
		num, ok := d["Value"].(json.Number)
		if !ok {
			continue
		}
		weight, err := strconv.ParseInt(string(num), 10, 64)
		if err != nil || weight == 0 {
			continue
		}
		description := desc
		signals = append(signals, Signal{Name: SignalSlug(desc), Weight: int(weight), Description: &description})
	}
	return signals, ipLeak
}

func identificationFromWebhookData(data map[string]any) *Identification {
	var flags DetectionFlags
	flagValues, _ := data["detection_flags"].(map[string]any)
	for _, name := range flagNames {
		*flags.field(name) = truthy(flagValues[name])
	}

	ts, _ := data["traffic_source"].(map[string]any)
	signals := []Signal{}
	if list, ok := data["signals"].([]any); ok {
		for _, item := range list {
			s, ok := item.(map[string]any)
			if !ok {
				continue
			}
			signals = append(signals, Signal{Name: str(s["name"]), Weight: toInt(s["weight"])})
		}
	}
	observedAt, _ := wire.ParseRFC3339(str(data["observed_at"]))

	return &Identification{
		RequestID:      str(data["request_id"]),
		VisitorID:      str(data["visitor_id"]),
		DeviceID:       str(data["device_id"]),
		SessionID:      str(data["session_id"]),
		CookieID:       str(data["cookie_id"]),
		UserHID:        nullableString(data["user_hid"]),
		Domain:         str(data["domain"]),
		PublicIP:       webhookIP(data["public_ip"]),
		LocalIP:        webhookIP(data["local_ip"]),
		ConnectionType: ConnectionType(str(data["connection_type"])),
		OS:             str(data["os"]),
		Browser:        str(data["browser"]),
		DeviceType:     str(data["device_type"]),
		TrafficSource: TrafficSource{
			Channel:        str(ts["channel"]),
			ReferrerDomain: str(ts["referrer_domain"]),
			LandingURL:     str(ts["landing_url"]),
			ClickIDType:    str(ts["click_id_type"]),
			UTMSource:      str(ts["utm_source"]),
			UTMMedium:      str(ts["utm_medium"]),
			UTMCampaign:    str(ts["utm_campaign"]),
			UTMContent:     str(ts["utm_content"]),
			UTMTerm:        str(ts["utm_term"]),
		},
		RiskScore:      toInt(data["risk_score"]),
		Signals:        signals,
		DetectionFlags: flags,
		ObservedAt:     observedAt,
		Source:         SourceWebhook,
		Raw:            data,
		ClientIdentity: parseClientIdentity(data["client_identity"]),
	}
}

func webhookIP(v any) IPInfo {
	m, _ := v.(map[string]any)
	return IPInfo{IP: normalizeIP(str(m["ip"])), Country: str(m["country"])}
}

// normalizeIP trims an IP value and turns the "no address" sentinels
// ("" and "0.0.0.0") into "".
func normalizeIP(s string) string {
	s = wire.Strip(s)
	if s == "0.0.0.0" {
		return ""
	}
	return s
}

// str returns a JSON string value, the literal of a JSON number, or "" for
// anything else (missing, null, boolean, array, object).
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

// nullableString returns nil for a missing, null or empty value.
func nullableString(v any) *string {
	s := str(v)
	if s == "" {
		return nil
	}
	return &s
}

// truthy converts a JSON value to a boolean: false, null, 0, "", [] and {}
// are false, everything else is true.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// toInt converts a JSON number to an int (fractions are truncated). Other
// values give 0.
func toInt(v any) int {
	return int(toInt64(v))
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return n
		}
		if f, err := x.Float64(); err == nil {
			return floatToInt64(f)
		}
	case float64:
		return floatToInt64(x)
	}
	return 0
}

func floatToInt64(f float64) int64 {
	if math.IsNaN(f) || f >= math.MaxInt64 || f <= math.MinInt64 {
		return 0
	}
	return int64(f)
}
