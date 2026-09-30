// Package wire holds the low-level parsing rules shared by the shieldlabs
// packages: whitespace trimming, timestamp formats and JSON decoding.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// isSpace reports whether r counts as whitespace when trimming wire values.
// It covers the Unicode whitespace set plus the ASCII information separators
// U+001C to U+001F.
func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Strip removes leading and trailing whitespace from s.
func Strip(s string) string {
	return strings.TrimFunc(s, isSpace)
}

var (
	// History rows: "YYYY-MM-DD HH:MM:SS[.fff]" in UTC. A zone designator is
	// tolerated and ignored because History timestamps are always UTC.
	historyTimeRE = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|[+-][0-9]{2}:?[0-9]{2})?$`)
	// Webhooks and the Management API: RFC 3339 with up to 9 fractional digits.
	rfc3339RE = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$`)
)

// ParseHistoryTime parses a History API created_at value
// ("YYYY-MM-DD HH:MM:SS" with optional fractional seconds, UTC). It reports
// false when the value is empty or malformed.
func ParseHistoryTime(s string) (time.Time, bool) {
	text := Strip(s)
	if text == "" {
		return time.Time{}, false
	}
	m := historyTimeRE.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, false
	}
	return build(m[1:7], m[7], 0)
}

// ParseRFC3339 parses an RFC 3339 timestamp with up to 9 fractional digits
// and a "Z" or "+HH:MM" zone, and returns it in UTC. It reports false when
// the value is malformed.
func ParseRFC3339(s string) (time.Time, bool) {
	// A single trailing line feed is tolerated, as in every ShieldLabs server SDK.
	s = strings.TrimSuffix(s, "\n")
	m := rfc3339RE.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	offset := 0
	if tz := m[8]; tz != "Z" {
		hh, _ := strconv.Atoi(tz[1:3])
		mm, _ := strconv.Atoi(tz[4:6])
		offset = hh*3600 + mm*60
		if tz[0] == '-' {
			offset = -offset
		}
	}
	return build(m[1:7], m[7], offset)
}

// build assembles a UTC time from year, month, day, hour, minute and second
// digits plus optional fractional digits, then removes the zone offset.
// Out-of-range components are rejected instead of being normalized.
func build(parts []string, frac string, offsetSeconds int) (time.Time, bool) {
	var n [6]int
	for i, p := range parts {
		n[i], _ = strconv.Atoi(p)
	}
	nanos := 0
	if frac != "" {
		nanos, _ = strconv.Atoi((frac + "000000000")[:9])
	}
	t := time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], nanos, time.UTC)
	if n[0] < 1 || t.Year() != n[0] || int(t.Month()) != n[1] || t.Day() != n[2] ||
		t.Hour() != n[3] || t.Minute() != n[4] || t.Second() != n[5] {
		return time.Time{}, false
	}
	return t.Add(-time.Duration(offsetSeconds) * time.Second), true
}

// Decode parses exactly one JSON value from b. Numbers are kept as
// json.Number so that integers never lose precision.
func Decode(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}

// DecodeObject parses b as one JSON object.
func DecodeObject(b []byte) (map[string]any, error) {
	v, err := Decode(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("the JSON value is not an object")
	}
	return m, nil
}
