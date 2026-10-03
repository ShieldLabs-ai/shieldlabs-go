package shieldlabs

import "github.com/ShieldLabs-ai/shieldlabs-go/internal/contract"

// These typed adapters retain the existing tolerant conversions while making
// incompatible schema changes fail compilation at each consuming field.
func stringField(v contract.Value[string]) string          { return str(v.Raw) }
func nullableStringField(v contract.Value[string]) *string { return nullableString(v.Raw) }
func integerField(v contract.Value[int64]) int             { return toInt(v.Raw) }
func integer64Field(v contract.Value[int64]) int64         { return toInt64(v.Raw) }
func booleanField(v contract.Value[bool]) bool             { return truthy(v.Raw) }
func integerRaw(v contract.Value[int64]) any               { return v.Raw }

func webhookFlags(v contract.DetectionFlags) map[string]contract.Value[bool] {
	return map[string]contract.Value[bool]{
		FlagVPN: v.VPN(), FlagPrivacyRelay: v.PrivacyRelay(),
		FlagBrowserVPNProxy: v.BrowserVPNProxy(), FlagTor: v.Tor(),
		FlagProxy: v.Proxy(), FlagDatacenterIP: v.DatacenterIP(),
		FlagAbuser: v.Abuser(), FlagOSMismatch: v.OSMismatch(),
		FlagOSNotDetected: v.OSNotDetected(), FlagTimezoneMismatch: v.TimezoneMismatch(),
		FlagAntiDetectBrowser: v.AntiDetectBrowser(), FlagBrowserAutomation: v.BrowserAutomation(),
		FlagIPMismatch: v.IPMismatch(), FlagIncognito: v.Incognito(),
		FlagSearchBot: v.SearchBot(), FlagSuspiciousPaidClick: v.SuspiciousPaidClick(),
		FlagJavaScriptDisabled: v.JavascriptDisabled(), FlagStunNotChecked: v.StunNotChecked(),
		FlagCheckIncomplete: v.CheckIncomplete(),
	}
}
