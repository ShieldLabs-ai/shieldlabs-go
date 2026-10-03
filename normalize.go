package shieldlabs

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/contract"
	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// historyFlagColumns selects schema-derived flag values. Two flags are derived.
func historyFlagColumns(row contract.HistoryRow) map[string]contract.Value[bool] {
	return map[string]contract.Value[bool]{
		FlagVPN:                 row.IsVPN(),
		FlagPrivacyRelay:        row.IsPrivacyRelay(),
		FlagTor:                 row.IsTor(),
		FlagProxy:               row.IsProxy(),
		FlagDatacenterIP:        row.IsDatacenter(),
		FlagAbuser:              row.IsAbuser(),
		FlagOSMismatch:          row.IsOSMismatch(),
		FlagOSNotDetected:       row.IsOSNotDetected(),
		FlagTimezoneMismatch:    row.IsTimezoneMismatch(),
		FlagAntiDetectBrowser:   row.IsAntidetect(),
		FlagBrowserAutomation:   row.IsBrowserAutomation(),
		FlagIncognito:           row.IsIncognito(),
		FlagSearchBot:           row.IsSearchBot(),
		FlagSuspiciousPaidClick: row.IsSuspiciousPaidClick(),
		FlagJavaScriptDisabled:  row.IsJsDisabled(),
		FlagStunNotChecked:      row.IsStunNotChecked(),
		FlagCheckIncomplete:     row.CheckIncomplete(),
	}
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

func identificationFromHistoryRow(raw map[string]any) *Identification {
	row := contract.ReadHistoryRow(raw)
	columns := historyFlagColumns(row)
	var localIP, localCountry string
	if src := wire.Strip(stringField(row.WebrtcLeakSource())); src != "" && src != "none" {
		localIP, localCountry = normalizeIP(stringField(row.WebrtcLeakIP())), stringField(row.WebrtcLeakCountry())
	} else {
		localIP, localCountry = normalizeIP(stringField(row.WebRtcIP())), stringField(row.WebRtcCountry())
	}
	publicIP := normalizeIP(stringField(row.IP()))

	signals, ipLeakDetail := historySignals(row.ScoreDetails())

	var flags DetectionFlags
	searchBot := booleanField(row.IsSearchBot())
	for _, name := range flagNames {
		var v bool
		switch name {
		case FlagBrowserVPNProxy:
			v = contract.String(row.ConnectionType()) == "browser_vpn_proxy"
		case FlagIPMismatch:
			v = !searchBot && (ipLeakDetail || (publicIP != "" && localIP != "" && publicIP != localIP))
		default:
			v = booleanField(columns[name])
		}
		*flags.field(name) = v
	}

	domain := stringField(row.SiteDomain())
	if domain == "" {
		domain = stringField(row.Domain())
	}
	observedAt, _ := wire.ParseHistoryTime(stringField(row.CreatedAt()))

	return &Identification{
		RequestID:      stringField(row.RequestID()),
		VisitorID:      stringField(row.VisitorID()),
		DeviceID:       stringField(row.DeviceID()),
		SessionID:      stringField(row.SessionID()),
		CookieID:       stringField(row.CookieID()),
		UserHID:        nullableStringField(row.UserHID()),
		Domain:         domain,
		PublicIP:       IPInfo{IP: publicIP, Country: stringField(row.Country())},
		LocalIP:        IPInfo{IP: localIP, Country: localCountry},
		ConnectionType: ConnectionType(stringField(row.ConnectionType())),
		OS:             stringField(row.OS()),
		Browser:        stringField(row.Browser()),
		DeviceType:     stringField(row.DeviceType()),
		TrafficSource: TrafficSource{
			Channel:        stringField(row.TrafficChannel()),
			ReferrerDomain: stringField(row.ReferrerDomain()),
			LandingURL:     stringField(row.EntryURL()),
			ClickIDType:    stringField(row.ClickIDType()),
			UTMSource:      stringField(row.UTMSource()),
			UTMMedium:      stringField(row.UTMMedium()),
			UTMCampaign:    stringField(row.UTMCampaign()),
			UTMContent:     stringField(row.UTMContent()),
			UTMTerm:        stringField(row.UTMTerm()),
		},
		RiskScore:      integerField(row.Score()),
		Signals:        signals,
		DetectionFlags: flags,
		ObservedAt:     observedAt,
		Source:         SourceHistory,
		Raw:            raw,
	}
}

// historySignals parses the score_details JSON string of a History row. It
// keeps the entries with a non-zero integer Value, in order, and reports
// whether an IP leak description was present (at any weight).
func historySignals(scoreDetails contract.Value[string]) ([]Signal, bool) {
	signals := []Signal{}
	text, _ := scoreDetails.Raw.(string)
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
		detail := contract.ReadScoreDetail(d)
		desc := contract.String(detail.Description())
		if strings.HasPrefix(desc, ipLeakPrefix) {
			ipLeak = true
		}
		num, ok := integerRaw(detail.Value()).(json.Number)
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

func identificationFromWebhookData(raw map[string]any) *Identification {
	data := contract.ReadIdentificationScoredData(raw)
	var flags DetectionFlags
	flagValues := webhookFlags(contract.ReadDetectionFlags(contract.Object[contract.DetectionFlags](data.DetectionFlags())))
	for _, name := range flagNames {
		*flags.field(name) = booleanField(flagValues[name])
	}

	ts := contract.ReadTrafficSource(contract.Object[contract.TrafficSource](data.TrafficSource()))
	signals := []Signal{}
	if list := contract.Array[contract.Signal](data.Signals()); list != nil {
		for _, item := range list {
			s, ok := item.(map[string]any)
			if !ok {
				continue
			}
			signal := contract.ReadSignal(s)
			signals = append(signals, Signal{Name: stringField(signal.Name()), Weight: integerField(signal.Weight())})
		}
	}
	observedAt, _ := wire.ParseRFC3339(stringField(data.ObservedAt()))

	return &Identification{
		RequestID:      stringField(data.RequestID()),
		VisitorID:      stringField(data.VisitorID()),
		DeviceID:       stringField(data.DeviceID()),
		SessionID:      stringField(data.SessionID()),
		CookieID:       stringField(data.CookieID()),
		UserHID:        nullableStringField(data.UserHID()),
		Domain:         stringField(data.Domain()),
		PublicIP:       webhookIP(data.PublicIP()),
		LocalIP:        webhookIP(data.LocalIP()),
		ConnectionType: ConnectionType(stringField(data.ConnectionType())),
		OS:             stringField(data.OS()),
		Browser:        stringField(data.Browser()),
		DeviceType:     stringField(data.DeviceType()),
		TrafficSource: TrafficSource{
			Channel:        stringField(ts.Channel()),
			ReferrerDomain: stringField(ts.ReferrerDomain()),
			LandingURL:     stringField(ts.LandingURL()),
			ClickIDType:    stringField(ts.ClickIDType()),
			UTMSource:      stringField(ts.UTMSource()),
			UTMMedium:      stringField(ts.UTMMedium()),
			UTMCampaign:    stringField(ts.UTMCampaign()),
			UTMContent:     stringField(ts.UTMContent()),
			UTMTerm:        stringField(ts.UTMTerm()),
		},
		RiskScore:      integerField(data.RiskScore()),
		Signals:        signals,
		DetectionFlags: flags,
		ObservedAt:     observedAt,
		Source:         SourceWebhook,
		Raw:            raw,
	}
}

func webhookIP(v contract.Value[contract.IpInfo]) IPInfo {
	m := contract.ReadIpInfo(contract.Object[contract.IpInfo](v))
	return IPInfo{IP: normalizeIP(stringField(m.IP())), Country: stringField(m.Country())}
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
