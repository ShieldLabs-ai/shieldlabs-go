package shieldlabs

import "encoding/json"

// Scoped server attribution. A verified provider does not verify a claimed agent.
type ClientIdentityClaim struct {
	ProfileID    string `json:"profile_id"`
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	AgentName    string `json:"agent_name"`
	Kind         string `json:"client_kind"`
	Purpose      string `json:"purpose"`
	Source       string `json:"source"`
}

type ClientIdentityAttribution struct {
	Subject     string   `json:"subject"`
	ValueID     string   `json:"value_id"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type ClientIdentityAssessment struct {
	ProfileID string `json:"candidate_profile_id,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

type ClientIdentityEvidence struct {
	CoveredComponents []string `json:"covered_components,omitempty"`
	RequestBinding    string   `json:"request_binding,omitempty"`
	ReplayPolicy      string   `json:"replay_policy,omitempty"`
	ID                string   `json:"id"`
	Method            string   `json:"method"`
	SourceID          string   `json:"source_id"`
	SourceRevision    string   `json:"source_revision"`
	CheckedAt         string   `json:"checked_at"`
	EvaluatedAt       string   `json:"evaluated_at"`
	CoveredAttributes []string `json:"covered_attributes"`
}

type ClientIdentity struct {
	SchemaVersion          string                      `json:"schema_version"`
	ClassificationRevision uint32                      `json:"classification_revision"`
	ClassifierVersion      string                      `json:"classifier_version"`
	RegistryRevision       string                      `json:"registry_revision"`
	Availability           string                      `json:"availability"`
	ObservedAt             string                      `json:"observed_at"`
	DecidedAt              string                      `json:"decided_at"`
	Claims                 []ClientIdentityClaim       `json:"claims"`
	Verified               []ClientIdentityAttribution `json:"verified"`
	Assessments            []ClientIdentityAssessment  `json:"assessments"`
	Evidence               []ClientIdentityEvidence    `json:"evidence"`
}

// parseClientIdentity never reclassifies a payload or fabricates a verified flag.
// Unknown attributes remain in Identification.Raw; malformed optional data is nil.
func parseClientIdentity(value any) *ClientIdentity {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"schema_version", "availability", "registry_revision", "observed_at"} {
		if _, ok := object[key].(string); !ok {
			return nil
		}
	}
	for _, key := range []string{"claims", "verified", "assessments", "evidence"} {
		if _, ok := object[key].([]any); !ok {
			return nil
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result ClientIdentity
	if json.Unmarshal(data, &result) != nil || result.ClassificationRevision == 0 {
		return nil
	}
	return &result
}
