package shieldlabs

import (
	"context"
	"iter"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ShieldLabs-ai/shieldlabs-go/internal/wire"
)

// LookupType selects the identifier a History search matches on.
type LookupType string

// The seven History lookup types.
const (
	// LookupIP matches the public IP address, written as a dotted IPv4
	// address.
	LookupIP LookupType = "ip"
	// LookupUserHID matches the User HID exactly (case-sensitive).
	LookupUserHID LookupType = "user_hid"
	// LookupVisitorID matches the visitor ID (UUID).
	LookupVisitorID LookupType = "visitor_id"
	// LookupRequestID matches the request ID (UUID).
	LookupRequestID LookupType = "request_id"
	// LookupDeviceID matches the device ID (UUID).
	LookupDeviceID LookupType = "device_id"
	// LookupSessionID matches the session ID (UUID).
	LookupSessionID LookupType = "session_id"
	// LookupCookieID matches the cookie ID (UUID).
	LookupCookieID LookupType = "cookie_id"
)

const (
	defaultSearchLimit = 20
	maxSearchLimit     = 100
	defaultPageSize    = 100
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// HistorySearchOptions controls one History page.
type HistorySearchOptions struct {
	// Limit is the page size, 1 to 100. Zero means the default of 20.
	Limit int
	// Offset is the number of rows to skip, 0 or more.
	Offset int
}

// HistoryIterateOptions controls [HistoryService.All].
type HistoryIterateOptions struct {
	// PageSize is the number of rows requested per page, 1 to 100. Zero means
	// 100.
	PageSize int
	// MaxItems stops the iteration after this many identifications. Zero
	// means no limit.
	MaxItems int
}

// HistoryPage is one page of History results, newest first.
type HistoryPage struct {
	// Data holds the identifications of this page.
	Data []*Identification `json:"data"`
	// Total is the number of rows matching the search.
	Total int64 `json:"total"`
}

// HistoryService searches the History API. Get it from [Client].History.
type HistoryService struct {
	c *Client
}

// Search returns one page of identifications whose lookup identifier equals
// value, newest first. Use it for account-abuse checks, for example to count
// how many accounts one device ID has signed up.
//
// Arguments are validated on the client before anything is sent, so that a
// typo never turns into an unfiltered or failing query: the lookup type must
// be one of the seven Lookup constants, UUID values must be UUIDs (sent
// lowercase), an IP must be a dotted IPv4 address, Limit must be 0 to 100 and
// Offset must not be negative. A User HID is matched exactly; it must be
// non-empty, valid UTF-8 text without "/" and other than "." and "..", because
// the History API cannot match such values in the request path. Invalid
// arguments return an error matching [ErrValidation].
func (s *HistoryService) Search(ctx context.Context, lookup LookupType, value string, opts *HistorySearchOptions) (*HistoryPage, error) {
	limit, offset := defaultSearchLimit, 0
	if opts != nil {
		if opts.Limit < 0 || opts.Limit > maxSearchLimit {
			return nil, validationError("the limit must be between 1 and %d (0 selects the default of %d)", maxSearchLimit, defaultSearchLimit)
		}
		if opts.Limit != 0 {
			limit = opts.Limit
		}
		if opts.Offset < 0 {
			return nil, validationError("the offset must not be negative")
		}
		offset = opts.Offset
	}
	normalized, err := validateLookup(lookup, value)
	if err != nil {
		return nil, err
	}
	return s.search(ctx, historyRequest(lookup, normalized, limit, offset))
}

// All returns an iterator over every identification whose lookup identifier
// equals value, newest first, fetching pages of opts.PageSize rows as it
// goes. It stops after the last row (as reported by the page total), at an
// empty page, after opts.MaxItems identifications, or when the loop breaks.
//
// Rows can shift between pages while new identifications arrive, so the
// iterator skips identifications it has already yielded (same request ID).
//
// When a request fails, or the arguments are invalid, the iterator yields a
// nil identification with the error and stops:
//
//	for ident, err := range client.History.All(ctx, shieldlabs.LookupDeviceID, deviceID, nil) {
//		if err != nil {
//			return err
//		}
//		fmt.Println(ident.RequestID, ident.RiskScore)
//	}
func (s *HistoryService) All(ctx context.Context, lookup LookupType, value string, opts *HistoryIterateOptions) iter.Seq2[*Identification, error] {
	return func(yield func(*Identification, error) bool) {
		pageSize, maxItems := defaultPageSize, 0
		if opts != nil {
			if opts.PageSize < 0 || opts.PageSize > maxSearchLimit {
				yield(nil, validationError("the page size must be between 1 and %d (0 selects %d)", maxSearchLimit, defaultPageSize))
				return
			}
			if opts.PageSize != 0 {
				pageSize = opts.PageSize
			}
			if opts.MaxItems < 0 {
				yield(nil, validationError("the maximum number of items must not be negative"))
				return
			}
			maxItems = opts.MaxItems
		}
		normalized, err := validateLookup(lookup, value)
		if err != nil {
			yield(nil, err)
			return
		}
		seen := make(map[string]struct{})
		yielded, offset := 0, 0
		for {
			page, err := s.search(ctx, historyRequest(lookup, normalized, pageSize, offset))
			if err != nil {
				yield(nil, err)
				return
			}
			if len(page.Data) == 0 {
				return
			}
			for _, ident := range page.Data {
				key := dedupeKey(ident)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				if !yield(ident, nil) {
					return
				}
				yielded++
				if maxItems > 0 && yielded >= maxItems {
					return
				}
			}
			offset += len(page.Data)
			if int64(offset) >= page.Total {
				return
			}
		}
	}
}

// dedupeKey identifies a row for the iterator. Rows are compared on their
// request ID; rows without a usable request ID (empty or the nil UUID, as on
// some rate-limit marker rows) are compared on their whole identity instead,
// so that distinct rows are never dropped.
func dedupeKey(ident *Identification) string {
	if ident.RequestID != "" && ident.RequestID != NilUUID {
		return ident.RequestID
	}
	return strings.Join([]string{
		ident.RequestID,
		str(ident.Raw["created_at"]),
		str(ident.Raw["ver"]),
		str(ident.Raw["ip"]),
		ident.DeviceID,
		ident.CookieID,
		strconv.Itoa(ident.RiskScore),
	}, "|")
}

// historyRequest builds the request for one page of a validated lookup. It
// is retried like every History request, 429 answers included, unless the
// caller marks it as a single attempt.
func historyRequest(lookup LookupType, value string, limit, offset int) apiRequest {
	return apiRequest{
		path: "/api/v1/history/" + string(lookup) + "/" + escapePathValue(value),
		query: url.Values{
			"limit":  {strconv.Itoa(limit)},
			"offset": {strconv.Itoa(offset)},
		},
		retry429: true,
	}
}

// search sends one History request and decodes the page.
func (s *HistoryService) search(ctx context.Context, r apiRequest) (*HistoryPage, error) {
	resp, err := s.c.t.get(ctx, r)
	if err != nil {
		return nil, err
	}
	return parseHistoryPage(resp)
}

// parseHistoryPage decodes a {"data": [...], "total": N} body.
func parseHistoryPage(resp *apiResponse) (*HistoryPage, error) {
	body, err := wire.DecodeObject(resp.body)
	if err != nil {
		return nil, &APIError{
			StatusCode: resp.status,
			Message:    "the response is not a History API page: " + err.Error(),
			Body:       resp.body,
			Header:     resp.header,
		}
	}
	page := &HistoryPage{Data: []*Identification{}, Total: toInt64(body["total"])}
	rows, _ := body["data"].([]any)
	for _, item := range rows {
		if row, ok := item.(map[string]any); ok {
			page.Data = append(page.Data, identificationFromHistoryRow(row))
		}
	}
	return page, nil
}

// validateLookup checks a lookup type and value and returns the value to send.
func validateLookup(lookup LookupType, value string) (string, error) {
	switch lookup {
	case LookupRequestID, LookupDeviceID, LookupVisitorID, LookupSessionID, LookupCookieID:
		if !uuidRE.MatchString(value) {
			return "", validationError("%s must be a UUID such as 3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53", lookup)
		}
		return strings.ToLower(value), nil
	case LookupIP:
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return "", validationError("ip must be a dotted IPv4 address such as 192.0.2.1")
		}
		return value, nil
	case LookupUserHID:
		switch {
		case value == "":
			return "", validationError("user_hid must not be empty")
		case strings.Contains(value, "/"):
			return "", validationError(`user_hid must not contain "/": the History API cannot match such a value`)
		case value == "." || value == "..":
			return "", validationError(`user_hid must not be "." or "..": the History API cannot match such a value`)
		case !utf8.ValidString(value):
			return "", validationError("user_hid must be valid UTF-8 text")
		}
		return value, nil
	}
	return "", validationError("unknown lookup type %q: use one of ip, user_hid, visitor_id, request_id, device_id, session_id, cookie_id", string(lookup))
}

// escapePathValue escapes a validated lookup value for the request path in
// the canonical form that the History API decodes: A-Z, a-z, 0-9 and
// - . _ ~ $ & + , : ; = @ stay as they are, every other byte becomes an
// upper-case %XX escape (including ! ' ( ) * and spaces). The server compares
// any other escaping literally, so for example "a%2Cb" would not match the
// User HID "a,b". Values never contain "/" (see validateLookup).
func escapePathValue(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if keepInPath(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

// keepInPath reports whether a byte stays unescaped in a canonical path.
func keepInPath(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~$&+,:;=@", c) >= 0
}
