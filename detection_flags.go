package shieldlabs

import "encoding/json"

// UnmarshalJSON accepts the current detection flag names and the previous
// names. A delivery that still uses privacy_relay, stun_not_checked,
// ws_tcp_latency or banned_ip sets the same flag. Marshaling writes only
// the current names.
func (f *DetectionFlags) UnmarshalJSON(data []byte) error {
	type current DetectionFlags
	var parsed current
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	var legacy struct {
		PrivacyRelay   bool `json:"privacy_relay"`
		StunNotChecked bool `json:"stun_not_checked"`
		LatencyTest    bool `json:"ws_tcp_latency"`
		BannedIP       bool `json:"banned_ip"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*f = DetectionFlags(parsed)
	f.PrivacyRelay = f.PrivacyRelay || legacy.PrivacyRelay
	f.StunNotChecked = f.StunNotChecked || legacy.StunNotChecked
	f.LatencyTest = f.LatencyTest || legacy.LatencyTest
	f.BannedIP = f.BannedIP || legacy.BannedIP
	return nil
}
