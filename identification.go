package shieldlabs

import "time"

// Identification is one run of the ShieldLabs agent in one browser: one
// billable request and one History row. Webhook deliveries and History API
// rows are both normalized into this model, and its JSON field names follow
// the webhook contract.
//
// Every field is always set. Unknown values (a new connection type, a new
// risk signal) are kept as they arrive.
type Identification struct {
	WebhookExtension
	// RequestID is the UUID the browser agent returned for this
	// identification. Use it to join the browser call, the webhook and the
	// History row, and to make sure one identification authorizes only one
	// protected action.
	RequestID string `json:"request_id"`

	// VisitorID is the server-side visitor identifier. It is sticky to the
	// device: a new cookie on a known device usually keeps the visitor ID.
	VisitorID string `json:"visitor_id"`

	// DeviceID is the server-side device identifier. It survives cleared
	// cookies and private windows. [NilUUID] means that the identification
	// had no usable device signals.
	DeviceID string `json:"device_id"`

	// SessionID identifies one visit on one origin.
	SessionID string `json:"session_id"`

	// CookieID is the first-party browser identifier kept by the agent.
	CookieID string `json:"cookie_id"`

	// UserHID is the hashed or pseudonymous account ID your page passed to the
	// agent. It is nil when none was stored. Anonymous checks use the value
	// "anonymous"; "fail", "-1" and "unknown" are other values that name no
	// account. Use [Identification.AccountUserHID] to skip all of them, for
	// example when counting the accounts of one device.
	UserHID *string `json:"user_hid"`

	// Domain is the registered domain the identification belongs to.
	Domain string `json:"domain"`

	// PublicIP is the IP address of the HTTP request and its country.
	PublicIP IPInfo `json:"public_ip"`

	// LocalIP is the local network address observed during the network
	// checks, and its country.
	LocalIP IPInfo `json:"local_ip"`

	// ConnectionType is the connection class, for example
	// [ConnectionTypeVPN]. Unknown values are kept.
	ConnectionType ConnectionType `json:"connection_type"`

	// OS is the operating system, for example "Windows" or "Mac OS X".
	OS string `json:"os"`

	// Browser is the browser, for example "Chrome" or "Safari".
	Browser string `json:"browser"`

	// DeviceType is "desktop", "mobile", "tablet" or "unknown".
	DeviceType string `json:"device_type"`

	// TrafficSource describes where the visit came from.
	TrafficSource TrafficSource `json:"traffic_source"`

	// RiskScore is an integer from 0 to 100. A value above 100 (999) is a
	// rate-limit marker, never a score: see [IsRateLimited]. Use [RiskBand]
	// for the band.
	RiskScore int `json:"risk_score"`

	// Signals lists the weighted risk signals behind the score, in the order
	// ShieldLabs reported them. Weights can be negative and names can repeat.
	// Use signals for display and logging, and branch on DetectionFlags and
	// RiskScore instead. Never add up the weights yourself.
	Signals []Signal `json:"signals"`

	// DetectionFlags holds the 19 stable detection booleans.
	DetectionFlags DetectionFlags `json:"detection_flags"`

	// ObservedAt is when the identification was observed, in UTC. For a
	// webhook it is the time the verdict was sent; for a History row it is
	// the time the identification was stored. It is the zero time when the
	// value could not be read.
	ObservedAt time.Time `json:"observed_at"`

	// Source tells whether the identification came from a webhook or from
	// the History API.
	Source Source `json:"source"`

	// Raw is the original webhook data object or History row, including
	// fields this model does not cover. Numbers are json.Number values so
	// that integers keep their exact value.
	Raw map[string]any `json:"-"`
}

// Band returns the risk band of the identification's Risk Score.
func (i *Identification) Band() Band {
	return RiskBand(i.RiskScore)
}

// IsRateLimited reports whether the Risk Score is the rate-limit marker.
func (i *Identification) IsRateLimited() bool {
	return IsRateLimited(i.RiskScore)
}

// AccountUserHID returns the User HID when it names one of your accounts. ok
// is false when UserHID is nil or one of the values that name no account
// (see [IsSentinelUserHID]). Use it when you count the accounts seen on one
// device, visitor or IP address:
//
//	accounts := map[string]bool{}
//	for _, ident := range page.Data {
//		if hid, ok := ident.AccountUserHID(); ok {
//			accounts[hid] = true
//		}
//	}
func (i *Identification) AccountUserHID() (userHID string, ok bool) {
	if i.UserHID == nil || IsSentinelUserHID(*i.UserHID) {
		return "", false
	}
	return *i.UserHID, true
}

// IsSentinelUserHID reports whether a User HID value names no account: the
// empty string, "anonymous" (anonymous checks) and the sentinel values
// "fail", "-1" and "unknown". The comparison is exact and case-sensitive.
func IsSentinelUserHID(userHID string) bool {
	switch userHID {
	case "", "anonymous", "fail", "-1", "unknown":
		return true
	}
	return false
}

// Source is the surface an [Identification] was read from.
type Source string

const (
	// SourceWebhook marks an identification parsed from a webhook delivery.
	SourceWebhook Source = "webhook"
	// SourceHistory marks an identification read from the History API.
	SourceHistory Source = "history"
)

// ConnectionType is the connection class of an identification. The set is
// open: values other than the constants below are kept as they arrive.
type ConnectionType string

// Known connection types.
const (
	ConnectionTypeDirect          ConnectionType = "direct"
	ConnectionTypeMobile          ConnectionType = "mobile"
	ConnectionTypeVPN             ConnectionType = "vpn"
	ConnectionTypeProxy           ConnectionType = "proxy"
	ConnectionTypeTor             ConnectionType = "tor"
	ConnectionTypePrivacyRelay    ConnectionType = "privacy_relay"
	ConnectionTypeBrowserVPNProxy ConnectionType = "browser_vpn_proxy"
	ConnectionTypeUnknown         ConnectionType = "unknown"
)

// IPInfo is an IP address and its country.
type IPInfo struct {
	// IP is a dotted IPv4 address, or "" when none is known (for example for
	// visitors on IPv6).
	IP string `json:"ip"`
	// Country is the English country name, for example "Germany", or ""
	// when unknown.
	Country string `json:"country"`
}

// TrafficSource describes where a visit came from. Every field is "" when
// unknown.
type TrafficSource struct {
	// Channel is the traffic channel, for example "Google Ads",
	// "Organic Search", "Referral" or "Direct".
	Channel string `json:"channel"`
	// ReferrerDomain is the referring site without "www.", or the crawler
	// name for search engine crawlers.
	ReferrerDomain string `json:"referrer_domain"`
	// LandingURL is the landing page URL without its fragment. It can contain
	// query string values.
	LandingURL string `json:"landing_url"`
	// ClickIDType is the ad click ID parameter found on the landing URL, for
	// example "gclid".
	ClickIDType string `json:"click_id_type"`
	UTMSource   string `json:"utm_source"`
	UTMMedium   string `json:"utm_medium"`
	UTMCampaign string `json:"utm_campaign"`
	UTMContent  string `json:"utm_content"`
	UTMTerm     string `json:"utm_term"`
}

// Signal is one weighted risk signal behind a Risk Score.
type Signal struct {
	// Name is the signal slug, for example [SignalProxy]. The set is open.
	Name string `json:"name"`
	// Weight is the signal's contribution. It can be negative (corrections).
	Weight int `json:"weight"`
	// Description is the human-readable description from a History row, or
	// nil for webhook signals. It is free text: never branch on it.
	Description *string `json:"description"`
}

// DetectionFlags holds the 19 stable detection booleans of an
// identification. Flags missing from a delivery are false.
type DetectionFlags struct {
	OSMismatch2         bool `json:"os_mismatch2,omitempty"`
	DeviceSpoofing      bool `json:"device_spoofing,omitempty"`
	LatencyTest         bool `json:"latency_test,omitempty"`
	BannedIP            bool `json:"banned_ip,omitempty"`
	VPN                 bool `json:"vpn"`
	PrivacyRelay        bool `json:"privacy_relay"`
	BrowserVPNProxy     bool `json:"browser_vpn_proxy"`
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
	JavaScriptDisabled  bool `json:"javascript_disabled"`
	StunNotChecked      bool `json:"stun_not_checked"`
	CheckIncomplete     bool `json:"check_incomplete"`
}

// Detection flag names as they appear on the wire. Use them with
// [DetectionFlags.Get] and [EvaluateOptions].BlockFlags.
const (
	FlagVPN                 = "vpn"
	FlagPrivacyRelay        = "privacy_relay"
	FlagBrowserVPNProxy     = "browser_vpn_proxy"
	FlagTor                 = "tor"
	FlagProxy               = "proxy"
	FlagDatacenterIP        = "datacenter_ip"
	FlagAbuser              = "abuser"
	FlagOSMismatch          = "os_mismatch"
	FlagOSNotDetected       = "os_not_detected"
	FlagTimezoneMismatch    = "timezone_mismatch"
	FlagAntiDetectBrowser   = "anti_detect_browser"
	FlagBrowserAutomation   = "browser_automation"
	FlagIPMismatch          = "ip_mismatch"
	FlagIncognito           = "incognito"
	FlagSearchBot           = "search_bot"
	FlagSuspiciousPaidClick = "suspicious_paid_click"
	FlagJavaScriptDisabled  = "javascript_disabled"
	FlagStunNotChecked      = "stun_not_checked"
	FlagCheckIncomplete     = "check_incomplete"
)

var flagNames = [...]string{
	FlagVPN, FlagPrivacyRelay, FlagBrowserVPNProxy, FlagTor, FlagProxy, FlagDatacenterIP,
	FlagAbuser, FlagOSMismatch, FlagOSNotDetected, FlagTimezoneMismatch, FlagAntiDetectBrowser,
	FlagBrowserAutomation, FlagIPMismatch, FlagIncognito, FlagSearchBot, FlagSuspiciousPaidClick,
	FlagJavaScriptDisabled, FlagStunNotChecked, FlagCheckIncomplete,
}

// DetectionFlagNames returns the 19 detection flag names in wire order.
func DetectionFlagNames() []string {
	return append([]string(nil), flagNames[:]...)
}

// field returns a pointer to the flag with the given wire name, or nil.
func (f *DetectionFlags) field(name string) *bool {
	switch name {
	case "os_mismatch2":
		return &f.OSMismatch2
	case "device_spoofing":
		return &f.DeviceSpoofing
	case "latency_test":
		return &f.LatencyTest
	case "banned_ip":
		return &f.BannedIP
	case FlagVPN:
		return &f.VPN
	case FlagPrivacyRelay:
		return &f.PrivacyRelay
	case FlagBrowserVPNProxy:
		return &f.BrowserVPNProxy
	case FlagTor:
		return &f.Tor
	case FlagProxy:
		return &f.Proxy
	case FlagDatacenterIP:
		return &f.DatacenterIP
	case FlagAbuser:
		return &f.Abuser
	case FlagOSMismatch:
		return &f.OSMismatch
	case FlagOSNotDetected:
		return &f.OSNotDetected
	case FlagTimezoneMismatch:
		return &f.TimezoneMismatch
	case FlagAntiDetectBrowser:
		return &f.AntiDetectBrowser
	case FlagBrowserAutomation:
		return &f.BrowserAutomation
	case FlagIPMismatch:
		return &f.IPMismatch
	case FlagIncognito:
		return &f.Incognito
	case FlagSearchBot:
		return &f.SearchBot
	case FlagSuspiciousPaidClick:
		return &f.SuspiciousPaidClick
	case FlagJavaScriptDisabled:
		return &f.JavaScriptDisabled
	case FlagStunNotChecked:
		return &f.StunNotChecked
	case FlagCheckIncomplete:
		return &f.CheckIncomplete
	}
	return nil
}

// Get returns the flag with the given wire name, for example
// [FlagBrowserAutomation]. ok is false for an unknown name.
func (f DetectionFlags) Get(name string) (value, ok bool) {
	p := f.field(name)
	if p == nil {
		return false, false
	}
	return *p, true
}

// Map returns the 19 flags keyed by their wire names.
func (f DetectionFlags) Map() map[string]bool {
	m := make(map[string]bool, len(flagNames))
	for _, name := range flagNames {
		m[name] = *f.field(name)
	}
	return m
}
