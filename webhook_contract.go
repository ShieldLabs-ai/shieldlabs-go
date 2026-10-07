package shieldlabs

// WebhookExtension is absent on older events and History API responses.
type WebhookExtension struct {
	SearchBotOwner string       `json:"search_bot_owner,omitempty"`
	AIBotOwner     string       `json:"ai_bot_owner,omitempty"`
	AIBrowserOwner string       `json:"ai_browser_owner,omitempty"`
	ResultVersion  string       `json:"result_version,omitempty"`
	ScoringVersion string       `json:"scoring_version,omitempty"`
	RiskEvents     []RiskEvent  `json:"risk_events,omitempty"`
	HRE            *HRE         `json:"hre,omitempty"`
	Fingerprint    *Fingerprint `json:"fingerprint,omitempty"`
}
type RiskEvent struct {
	Code         string `json:"code"`
	Detected     bool   `json:"detected"`
	Weight       int    `json:"weight"`
	Contribution int    `json:"contribution"`
	Status       string `json:"status"`
}
type HREResult struct {
	ClusterID  *string `json:"cluster_id"`
	Status     string  `json:"status"`
	Level      *string `json:"level"`
	Reason     string  `json:"reason"`
	Devices    *int    `json:"devices,omitempty"`
	MinDevices *int    `json:"min_devices,omitempty"`
}
type HRE struct {
	RulesVersion     string    `json:"rules_version,omitempty"`
	AccountSharing   HREResult `json:"account_sharing"`
	AccountTakeover  HREResult `json:"account_takeover"`
	ImpossibleTravel HREResult `json:"impossible_travel"`
}
type Fingerprint struct {
	Outcome      string         `json:"outcome"`
	HardwareID   string         `json:"hardware_id,omitempty"`
	RecordID     string         `json:"record_id,omitempty"`
	RulesVersion string         `json:"rules_version"`
	Sharing      map[string]any `json:"sharing,omitempty"`
	Takeover     map[string]any `json:"takeover,omitempty"`
	Travel       map[string]any `json:"travel,omitempty"`
}
