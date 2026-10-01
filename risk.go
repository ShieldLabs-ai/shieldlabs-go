package shieldlabs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"
)

// Band is a risk band derived from a Risk Score. Bands are computed on the
// client; they are not part of the wire format.
type Band string

// Risk bands.
const (
	// BandTrusted covers scores 0 to 29.
	BandTrusted Band = "trusted"
	// BandSuspicious covers scores 30 to 59.
	BandSuspicious Band = "suspicious"
	// BandDangerous covers scores 60 to 100.
	BandDangerous Band = "dangerous"
	// BandRateLimited marks a score above 100 (999): the rate-limit marker,
	// which is not a score.
	BandRateLimited Band = "rate_limited"
)

// RiskBand returns the band of a Risk Score: trusted (0-29), suspicious
// (30-59) or dangerous (60-100). Scores above 100 are the rate-limit marker
// and return [BandRateLimited].
func RiskBand(score int) Band {
	switch {
	case score > 100:
		return BandRateLimited
	case score >= 60:
		return BandDangerous
	case score >= 30:
		return BandSuspicious
	}
	return BandTrusted
}

// IsRateLimited reports whether a Risk Score is the rate-limit marker (a
// value above 100, in practice 999). ShieldLabs writes one such
// identification when a visitor IP goes over the identification rate limit;
// it carries no real verdict. Request IDs issued while that IP is blocked get
// no identification at all, so [IdentificationsService.Get] returns nil for
// them: treat them as unverified.
func IsRateLimited(score int) bool {
	return score > 100
}

// DefaultMaxAge is the default freshness window of [EvaluateIdentification].
const DefaultMaxAge = 5 * time.Minute

// Reason explains why [EvaluateIdentification] refused an identification.
type Reason string

// Refusal reasons, in the order EvaluateIdentification checks them.
const (
	// ReasonMissing: no identification was found. Treat it as unverified,
	// never as clean.
	ReasonMissing Reason = "missing"
	// ReasonReplayed: the IsReplay callback reported the request ID as
	// already used.
	ReasonReplayed Reason = "replayed"
	// ReasonStale: the identification is older than MaxAge, or its time is
	// unknown.
	ReasonStale Reason = "stale"
	// ReasonRateLimited: the Risk Score is the rate-limit marker.
	ReasonRateLimited Reason = "rate_limited"
	// ReasonNoDeviceSignals: the device ID is the nil UUID.
	ReasonNoDeviceSignals Reason = "no_device_signals"
	// ReasonBlockedFlag: a flag listed in BlockFlags is set (see
	// Evaluation.Flag).
	ReasonBlockedFlag Reason = "blocked_flag"
	// ReasonBlockedBand: the risk band is listed in BlockBands.
	ReasonBlockedBand Reason = "blocked_band"
)

// EvaluateOptions tunes [EvaluateIdentification]. The zero value applies the
// defaults, which are a starting point to adjust for your traffic.
type EvaluateOptions struct {
	// MaxAge is the freshness window measured from ObservedAt. Zero means
	// DefaultMaxAge (5 minutes); a negative value disables the check.
	MaxAge time.Duration
	// Now is the current time. The zero value means time.Now().
	Now time.Time
	// BlockBands lists the bands to refuse. Nil means [BandDangerous]; an
	// empty, non-nil slice refuses no band.
	BlockBands []Band
	// BlockFlags lists detection flag names to refuse, checked in order. Nil
	// means FlagBrowserAutomation and FlagJavaScriptDisabled; an empty,
	// non-nil slice refuses no flag. Unknown names are ignored.
	BlockFlags []string
	// IsReplay reports whether a request ID was used before. The SDK stores
	// nothing itself: record each request ID in your own store (atomically)
	// and return true when it was already there. Return true as well when the
	// store cannot be reached, so that failures refuse rather than allow.
	IsReplay func(requestID string) bool
}

// Evaluation is the result of [EvaluateIdentification].
type Evaluation struct {
	// OK is true when no check refused the identification.
	OK bool `json:"ok"`
	// Reason is the first check that refused it, or "" when OK.
	Reason Reason `json:"reason"`
	// Band is the risk band of the identification, or "" when it is missing.
	Band Band `json:"band"`
	// Flag is the blocking flag when Reason is ReasonBlockedFlag.
	Flag string `json:"flag,omitempty"`
}

// EvaluateIdentification applies a reusable guard policy to an
// identification before a protected action such as a signup. It checks, in
// this order:
//
//  1. missing: ident is nil (never treat a missing identification as clean);
//  2. replayed: opts.IsReplay reports the request ID as already used;
//  3. stale: the identification is older than opts.MaxAge;
//  4. rate_limited: the Risk Score is the rate-limit marker;
//  5. no_device_signals: the device ID is the nil UUID;
//  6. blocked_flag: a flag in opts.BlockFlags is set;
//  7. blocked_band: the risk band is in opts.BlockBands.
//
// It never performs I/O.
func EvaluateIdentification(ident *Identification, opts EvaluateOptions) Evaluation {
	if ident == nil {
		return Evaluation{Reason: ReasonMissing}
	}
	band := RiskBand(ident.RiskScore)
	refuse := func(r Reason) Evaluation { return Evaluation{Reason: r, Band: band} }

	if opts.IsReplay != nil && opts.IsReplay(ident.RequestID) {
		return refuse(ReasonReplayed)
	}
	maxAge := opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	if maxAge > 0 {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		if ident.ObservedAt.IsZero() || now.Sub(ident.ObservedAt) > maxAge {
			return refuse(ReasonStale)
		}
	}
	if IsRateLimited(ident.RiskScore) {
		return refuse(ReasonRateLimited)
	}
	if ident.DeviceID == NilUUID {
		return refuse(ReasonNoDeviceSignals)
	}
	blockFlags := opts.BlockFlags
	if blockFlags == nil {
		blockFlags = []string{FlagBrowserAutomation, FlagJavaScriptDisabled}
	}
	for _, name := range blockFlags {
		if set, known := ident.DetectionFlags.Get(name); known && set {
			e := refuse(ReasonBlockedFlag)
			e.Flag = name
			return e
		}
	}
	blockBands := opts.BlockBands
	if blockBands == nil {
		blockBands = []Band{BandDangerous}
	}
	if slices.Contains(blockBands, band) {
		return refuse(ReasonBlockedBand)
	}
	return Evaluation{OK: true, Band: band}
}

// UserHID derives a stable, irreversible User HID from your own user ID:
// the lowercase hex HMAC-SHA256 of userID keyed with secret (64 characters).
// Compute it on your server with a secret that never reaches the browser,
// then pass the result to the browser agent instead of a raw email address
// or account ID.
//
// It returns an error matching [ErrValidation] when userID or secret is
// empty.
func UserHID(userID, secret string) (string, error) {
	if userID == "" {
		return "", validationError("the user ID is empty")
	}
	if secret == "" {
		return "", validationError("the secret is empty")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
