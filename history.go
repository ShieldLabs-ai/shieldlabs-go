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

// History lookup types. request_id is a legacy alias of identification_id.
const (
	// LookupIP matches the public IP address, written as a dotted IPv4
	// address.
	LookupIP LookupType = "ip"
	// LookupUserHID matches the User HID exactly (case-sensitive).
	LookupUserHID LookupType = "user_hid"
	// LookupVisitorID matches the visitor ID (UUID).
	LookupVisitorID LookupType = "visitor_id"
	// LookupIdentificationID matches one identification (UUID).
	LookupIdentificationID LookupType = "identification_id"
	// LookupRequestID is the legacy alias of LookupIdentificationID.
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
	// Offset is refused. Continue with the page token from the previous response.
	Offset int
	// Query holds flat filters such as risk_bands, is_vpn ("true" or "false"),
	// source and campaign. Repeated keys are repeated query parameters.
	Query url.Values
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
	// NextPageToken is the opaque cursor returned by the server, if present.
	NextPageToken *string `json:"next_page_token,omitempty"`
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
// be one of the Lookup constants. request_id is a legacy alias of
// identification_id. UUID values must be UUIDs (sent
// lowercase), an IP must be a dotted IPv4 address, Limit must be 0 to 100 and
// Offset must not be negative. A User HID is matched exactly; it must be
// non-empty, valid UTF-8 text without "/" and other than "." and "..", because
// the History API cannot match such values in the request path. Invalid
// arguments return an error matching [ErrValidation].
func (s *HistoryService) Search(ctx context.Context, lookup LookupType, value string, opts *HistorySearchOptions) (*HistoryPage, error) {
	limit := defaultSearchLimit
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
		if opts.Offset != 0 {
			return nil, validationError("offset is not accepted. Continue with page_token.")
		}
	}
	normalized, err := validateLookup(lookup, value)
	if err != nil {
		return nil, err
	}
	var extra url.Values
	if opts != nil {
		extra = opts.Query
	}
	req, err := s.historyRequest(lookup, normalized, limit, extra)
	if err != nil {
		return nil, err
	}
	return s.search(ctx, req)
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
//		fmt.Println(ident.IdentificationID, ident.RiskScore)
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
			req, err := s.historyRequest(lookup, normalized, pageSize, nil)
			if err != nil {
				yield(nil, err)
				return
			}
			page, err := s.search(ctx, req)
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
	if ident.IdentificationID != "" && ident.IdentificationID != NilUUID {
		return ident.IdentificationID
	}
	return strings.Join([]string{
		ident.IdentificationID,
		str(ident.Raw["created_at"]),
		str(ident.Raw["ver"]),
		str(ident.Raw["ip"]),
		ident.DeviceID,
		ident.CookieID,
		strconv.Itoa(ident.RiskScore),
	}, "|")
}

// historyRequest builds one domain-scoped History card read. Offset is not sent.
func (s *HistoryService) historyRequest(lookup LookupType, value string, limit int, extra url.Values) (apiRequest, error) {
	resource, err := historyResource(lookup)
	if err != nil {
		return apiRequest{}, err
	}
	prefix, err := s.c.domainPrefix()
	if err != nil {
		return apiRequest{}, err
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	for key, values := range extra {
		for _, item := range values {
			query.Add(key, item)
		}
	}
	return apiRequest{
		path:     prefix + "/history/" + resource + "/" + escapePathValue(value),
		query:    query,
		retry429: true,
	}, nil
}

// List reads one page of identifications or user rows for the client's domain.
// visitor, device and ip lists are not accepted.
func (s *HistoryService) List(ctx context.Context, resource string, opts *HistorySearchOptions) (*EntityPage, error) {
	if resource != "identifications" && resource != "user" {
		return nil, validationError("list supports identifications and user")
	}
	limit := defaultSearchLimit
	var extra url.Values
	if opts != nil {
		if opts.Limit < 0 || opts.Limit > maxSearchLimit {
			return nil, validationError("the limit must be between 1 and %d (0 selects the default of %d)", maxSearchLimit, defaultSearchLimit)
		}
		if opts.Limit != 0 {
			limit = opts.Limit
		}
		if opts.Offset != 0 {
			return nil, validationError("offset is not accepted. Continue with page_token.")
		}
		extra = opts.Query
	}
	if ids, ok := extra["ids"]; ok {
		if resource != "user" || len(ids) != 1 || ids[0] == "" || len(ids[0]) > 512 {
			return nil, validationError("ids must contain one user id on the user list")
		}
	}
	prefix, err := s.c.domainPrefix()
	if err != nil {
		return nil, err
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	for key, values := range extra {
		for _, item := range values {
			query.Add(key, item)
		}
	}
	resp, err := s.c.t.get(ctx, apiRequest{path: prefix + "/history/" + resource, query: query, retry429: true})
	if err != nil {
		return nil, err
	}
	return parseCurrentEntityPage(resp)
}

func historyResource(lookup LookupType) (string, error) {
	switch lookup {
	case LookupIdentificationID, LookupRequestID:
		return "identifications", nil
	case LookupUserHID:
		return "user", nil
	case LookupVisitorID:
		return "visitor", nil
	case LookupDeviceID:
		return "device", nil
	case LookupIP:
		return "ip", nil
	default:
		return "", validationError("that lookup is not a History resource. Use identifications, user, visitor, device or ip.")
	}
}

// Domain is one site this key can read.
type Domain struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

// Domains lists the domains for this key. ID is the only legal domain id.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	resp, err := c.t.get(ctx, apiRequest{path: "/api/v1/domains", retry429: true})
	if err != nil {
		return nil, err
	}
	body, err := wire.DecodeObject(resp.body)
	if err != nil {
		return nil, &APIError{StatusCode: resp.status, Message: "the response is not a domain list: " + err.Error(), Body: resp.body, Header: resp.header}
	}
	rows, _ := body["domains"].([]any)
	out := make([]Domain, 0, len(rows))
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := row["id"].(string)
		domain, _ := row["domain"].(string)
		if id == "" || domain == "" {
			continue
		}
		out = append(out, Domain{ID: strings.ToLower(id), Domain: domain})
	}
	return out, nil
}

func (c *Client) domainPrefix() (string, error) {
	if !uuidRE.MatchString(c.domainID) {
		return "", validationError("domain_id must be the public domain UUID from domains()")
	}
	return "/api/v1/domains/" + strings.ToLower(c.domainID), nil
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
	if card, ok := body["data"].(map[string]any); ok {
		rows = []any{card}
	}
	for _, item := range rows {
		if row, ok := item.(map[string]any); ok {
			ident, err := identificationFromEntityOrRow(row)
			if err != nil {
				return nil, err
			}
			page.Data = append(page.Data, ident)
		}
	}
	if _, present := body["total"]; !present {
		page.Total = int64(len(page.Data))
	}
	if token, ok := body["next_page_token"].(string); ok {
		page.NextPageToken = &token
	}
	return page, nil
}

// validateLookup checks a lookup type and value and returns the value to send.
func validateLookup(lookup LookupType, value string) (string, error) {
	switch lookup {
	case LookupIdentificationID, LookupRequestID, LookupDeviceID, LookupVisitorID, LookupSessionID, LookupCookieID:
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
	return "", validationError("unknown lookup type %q: use one of ip, user_hid, visitor_id, identification_id, request_id, device_id, session_id, cookie_id", string(lookup))
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
