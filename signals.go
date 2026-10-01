package shieldlabs

import (
	"strings"
	"unicode"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// Known risk signal names ([Signal].Name). The set is open: new signals can
// appear at any time, so treat names as strings and never as a closed enum.
const (
	SignalTor                    = "tor"
	SignalJavaScriptDisabled     = "javascript_disabled"
	SignalOSMismatch             = "os_mismatch"
	SignalAntidetectBrowser      = "antidetect_browser"
	SignalProxyRoutedAntidetect  = "proxy_routed_antidetect"
	SignalPortScanRoutedViaProxy = "port_scan_routed_via_proxy"
	SignalBrowserAutomation      = "browser_automation"
	SignalStunNotChecked         = "stun_not_checked"
	SignalStunLateCorrection     = "stun_late_correction"
	SignalOSNotDetected          = "os_not_detected"
	SignalBrowserVPNProxy        = "browser_vpn_proxy"
	SignalVPN                    = "vpn"
	SignalPrivacyRelay           = "privacy_relay"
	SignalProxy                  = "proxy"
	SignalDatacenterIP           = "datacenter_ip"
	SignalAbuser                 = "abuser"
	SignalTimezoneMismatch       = "timezone_mismatch"
	SignalRateLimited            = "rate_limited"
)

var exactSignalSlugs = map[string]string{
	"Is tor":                                    SignalTor,
	"Is VPN":                                    SignalVPN,
	"Is privacy relay":                          SignalPrivacyRelay,
	"Is proxy":                                  SignalProxy,
	"Is datacenter":                             SignalDatacenterIP,
	"Is abuser":                                 SignalAbuser,
	"Stun is not checked":                       SignalStunNotChecked,
	"Stun passed (late arrival, corrected)":     SignalStunLateCorrection,
	"UA OS is not detected":                     SignalOSNotDetected,
	"Network OS is not detected":                SignalOSNotDetected,
	"Browser timezone ≠ IP-timezone":            SignalTimezoneMismatch,
	"Browser VPN/Proxy":                         SignalBrowserVPNProxy,
	"Browser Automation":                        SignalBrowserAutomation,
	"User has been banned 1H, to many requests": SignalRateLimited,
	"Port scan routed via proxy (antidetect browser pattern)": SignalProxyRoutedAntidetect,
}

var prefixSignalSlugs = []struct{ prefix, slug string }{
	{"Antidetect browser", SignalAntidetectBrowser},
	{"Os_mismatch", SignalOSMismatch},
	{"OS mismatch2", "os_mismatch2"},
	{"TCP handshake", "tcp_handshake_v2"},
	{"Latency test", "ws_tcp_latency"},
	{"JavaScript disabled", SignalJavaScriptDisabled},
}

const stickyVerdictPrefix = "Sticky verdict: "

// SignalSlug returns the signal name that ShieldLabs derives from a signal
// description. History rows carry descriptions (score_details) while webhooks
// carry names; the History client uses this function so that both surfaces
// report the same names.
//
// Known descriptions map to fixed names. Any other description is slugified:
// the text before the first "(" is lowercased, spaces, "-" and "/" become
// "_", "≠" becomes "_neq_" and other punctuation is dropped. An empty result
// becomes "unknown".
func SignalSlug(description string) string {
	if slug, ok := exactSignalSlugs[description]; ok {
		return slug
	}
	for _, p := range prefixSignalSlugs {
		if strings.HasPrefix(description, p.prefix) {
			return p.slug
		}
	}
	if strings.HasPrefix(description, stickyVerdictPrefix) {
		rest := description[strings.Index(description, ":")+1:]
		return fallbackSlug(wire.Strip(rest))
	}
	return fallbackSlug(description)
}

// fallbackSlug slugifies a free-text signal description.
func fallbackSlug(description string) string {
	desc := wire.Strip(description)
	if i := strings.Index(desc, "("); i >= 0 {
		desc = wire.Strip(desc[:i])
	}
	var b strings.Builder
	prevSep := false
	for _, r := range desc {
		switch {
		case r == ' ' || r == '-' || r == '/':
			if !prevSep && b.Len() > 0 {
				b.WriteByte('_')
				prevSep = true
			}
		case r == '≠':
			b.WriteString("_neq_")
			prevSep = false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteString(lowerRune(r))
			prevSep = false
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		return "unknown"
	}
	return s
}

// lowerRune lowercases one character with the full Unicode mapping, where
// U+0130 (capital I with dot above) becomes "i" plus a combining dot.
func lowerRune(r rune) string {
	if r == 'İ' {
		return "i̇"
	}
	return string(unicode.ToLower(r))
}
