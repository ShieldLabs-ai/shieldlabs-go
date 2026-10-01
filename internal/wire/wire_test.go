package wire

import (
	"encoding/json"
	"testing"
	"time"
)

const layout = "2006-01-02T15:04:05.000000000Z07:00"

func TestParseHistoryTime(t *testing.T) {
	valid := map[string]string{
		"2026-09-30 12:34:56.123":       "2026-09-30T12:34:56.123000000Z",
		"2026-09-30 12:34:56":           "2026-09-30T12:34:56.000000000Z",
		"2026-09-30 12:34:56.5":         "2026-09-30T12:34:56.500000000Z",
		"2026-09-30 12:34:56.123456789": "2026-09-30T12:34:56.123456789Z",
		"2026-09-30T12:34:56.123":       "2026-09-30T12:34:56.123000000Z",
		" 2026-09-30 12:34:56.123\n":    "2026-09-30T12:34:56.123000000Z",
		"2026-09-30 12:34:56.123Z":      "2026-09-30T12:34:56.123000000Z",
		"2026-09-30 12:34:56+05:00":     "2026-09-30T12:34:56.000000000Z",
		"2026-09-30 12:34:56-0300":      "2026-09-30T12:34:56.000000000Z",
		"2024-02-29 00:00:00":           "2024-02-29T00:00:00.000000000Z",
		"\x1f2026-09-30 12:34:56 ":      "2026-09-30T12:34:56.000000000Z",
	}
	for in, want := range valid {
		got, ok := ParseHistoryTime(in)
		if !ok || got.Format(layout) != want || got.Location() != time.UTC {
			t.Errorf("ParseHistoryTime(%q) = %s, %v; want %s", in, got.Format(layout), ok, want)
		}
	}
	invalid := []string{
		"", "   ", "2026-09-30", "2026-09-30 12:34", "2026-09-30 12:34:56.1234567890",
		"2026-13-01 00:00:00", "2026-02-30 00:00:00", "2026-09-30 24:00:00", "2026-09-30 12:60:00",
		"2026-09-30 12:34:60", "0000-01-01 00:00:00", "2026/09/30 12:34:56", "2026-09-30 12:34:56.",
		"2026-09-30t12:34:56",
	}
	for _, in := range invalid {
		if got, ok := ParseHistoryTime(in); ok || !got.IsZero() {
			t.Errorf("ParseHistoryTime(%q) = %s, %v; want failure", in, got, ok)
		}
	}
}

func TestParseRFC3339(t *testing.T) {
	valid := map[string]string{
		"2026-09-30T12:34:57.482913041Z": "2026-09-30T12:34:57.482913041Z",
		"2026-09-30T12:34:56Z":           "2026-09-30T12:34:56.000000000Z",
		"2026-09-30T13:10:00.5Z":         "2026-09-30T13:10:00.500000000Z",
		"2026-09-30T14:34:56+02:00":      "2026-09-30T12:34:56.000000000Z",
		"2026-09-30T00:30:00-01:30":      "2026-09-30T02:00:00.000000000Z",
		"2026-09-30T23:30:00.1-01:00":    "2026-10-01T00:30:00.100000000Z",
		"2026-09-30T12:34:56Z\n":         "2026-09-30T12:34:56.000000000Z",
		"2026-01-15T09:00:00Z":           "2026-01-15T09:00:00.000000000Z",
	}
	for in, want := range valid {
		got, ok := ParseRFC3339(in)
		if !ok || got.Format(layout) != want || got.Location() != time.UTC {
			t.Errorf("ParseRFC3339(%q) = %s, %v; want %s", in, got.Format(layout), ok, want)
		}
	}
	invalid := []string{
		"", "2026-09-30 12:34:56Z", "2026-09-30T12:34:56", "2026-09-30T12:34:56z", "2026-09-30t12:34:56Z",
		"2026-09-30T12:34:56+0200", " 2026-09-30T12:34:56Z", "2026-09-30T12:34:56Z\n\n",
		"2026-09-30T12:34:56.1234567890Z", "2026-02-30T00:00:00Z", "0001-01-01T00:00:00",
	}
	for _, in := range invalid {
		if got, ok := ParseRFC3339(in); ok || !got.IsZero() {
			t.Errorf("ParseRFC3339(%q) = %s, %v; want failure", in, got, ok)
		}
	}
	zero, ok := ParseRFC3339("0001-01-01T00:00:00Z")
	if !ok || !zero.IsZero() {
		t.Errorf("the zero RFC 3339 time parses to the zero time.Time: %s %v", zero, ok)
	}
}

func TestStrip(t *testing.T) {
	if got := Strip("\x1c\x1d\t hello 　\x1e\x1f"); got != "hello" {
		t.Errorf("Strip = %q", got)
	}
}

func TestDecode(t *testing.T) {
	v, err := Decode([]byte(` {"n": 12345678901234567890, "f": 1.5} `))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["n"] != json.Number("12345678901234567890") || m["f"] != json.Number("1.5") {
		t.Errorf("numbers must stay exact: %#v", m)
	}
	for _, bad := range []string{``, `{`, `{} {}`, `{}]`, `nul`} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("Decode(%q): expected an error", bad)
		}
	}
	for _, notObject := range []string{`[]`, `null`, `1`, `"x"`} {
		if _, err := DecodeObject([]byte(notObject)); err == nil {
			t.Errorf("DecodeObject(%q): expected an error", notObject)
		}
	}
}
