package shieldlabs

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var errInvalidEntity = errors.New("invalid entity")

// EntityPage is one domain-scoped History page. It has no total: include_total
// is not sent, and a count on the body is not exposed.
type EntityPage struct {
	Data          []map[string]any
	NextPageToken *string
}

// EntityListOptions selects one page of identifications or users.
type EntityListOptions struct {
	From      string
	To        string
	Limit     int
	PageToken string
	// Filter is a JSON object with optional "identification" and "entity"
	// objects. Identification keys are risk_bands, hre_min_accounts and
	// hre_min_devices. Entity keys are ids and risk_bands.
	Filter map[string]any
}

// EntityGetOptions selects the window of one entity card.
type EntityGetOptions struct {
	From string
	To   string
}

// Entities reads domain-scoped History lists and cards. Get it from
// [Client].Entities. The legacy [Client].History search is unchanged.
type Entities struct {
	c *Client
}

// List returns one page of identifications or users for a public domain UUID.
func (s *Entities) List(ctx context.Context, domain, resource string, opts *EntityListOptions) (*EntityPage, error) {
	if resource != "identifications" && resource != "user" {
		return nil, validationError("only identifications and user have lists")
	}
	path, err := entityBase(domain, resource)
	if err != nil {
		return nil, err
	}
	limit := defaultSearchLimit
	query := url.Values{}
	if opts != nil {
		if err := entityWindow(query, opts.From, opts.To); err != nil {
			return nil, err
		}
		if opts.Limit < 0 || opts.Limit > maxSearchLimit {
			return nil, validationError("limit must be from 1 through %d", maxSearchLimit)
		}
		if opts.Limit != 0 {
			limit = opts.Limit
		}
		if opts.PageToken != "" {
			if len(opts.PageToken) > 4096 {
				return nil, validationError("invalid page_token")
			}
			query.Set("page_token", opts.PageToken)
		}
		if opts.Filter != nil {
			raw, err := encodeEntityFilter(opts.Filter)
			if err != nil {
				return nil, err
			}
			query.Set("filter", raw)
		}
	}
	query.Set("limit", strconv.Itoa(limit))
	resp, err := s.c.t.get(ctx, apiRequest{path: path, query: query, retry429: true})
	if err != nil {
		return nil, err
	}
	page, err := parseEntityPage(resp)
	if err != nil {
		return nil, err
	}
	if err := checkEntityPage(page, domain, resource, limit); err != nil {
		return nil, invalidEntity(resp)
	}
	return page, nil
}

// Get returns one entity card. The response body is {"data": {...}}.
func (s *Entities) Get(ctx context.Context, domain, resource, id string, opts *EntityGetOptions) (map[string]any, error) {
	path, err := entityBase(domain, resource)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeEntityID(resource, id)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if opts != nil {
		if err := entityWindow(query, opts.From, opts.To); err != nil {
			return nil, err
		}
	}
	resp, err := s.c.t.get(ctx, apiRequest{
		path:     path + "/" + escapePathValue(normalized),
		query:    query,
		retry429: true,
	})
	if err != nil {
		return nil, err
	}
	body, err := decodeObject(resp)
	if err != nil {
		return nil, err
	}
	entity, err := parseEntity(body["data"])
	if err != nil {
		return nil, err
	}
	if !entityMatches(entity, domain, resource, normalized) {
		return nil, invalidEntity(resp)
	}
	return entity, nil
}

func entityBase(domain, resource string) (string, error) {
	if !uuidRE.MatchString(domain) {
		return "", validationError("domain must be the public domain UUID")
	}
	switch resource {
	case "identifications", "user", "visitor", "device", "ip":
	default:
		return "", validationError("unknown History resource")
	}
	return "/api/v1/domains/" + strings.ToLower(domain) + "/history/" + resource, nil
}

func entityWindow(query url.Values, from, to string) error {
	if (from == "") != (to == "") {
		return validationError("send both from and to, or neither")
	}
	if from == "" {
		return nil
	}
	start, err := time.Parse(time.RFC3339, from)
	if err != nil {
		return validationError("History dates must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, to)
	if err != nil {
		return validationError("History dates must be RFC3339")
	}
	if !start.Before(end) {
		return validationError("from must be before to")
	}
	query.Set("from", from)
	query.Set("to", to)
	return nil
}

func encodeEntityFilter(filter map[string]any) (string, error) {
	for key := range filter {
		if key != "identification" && key != "entity" {
			return "", validationError("unsupported History filter")
		}
	}
	if raw, ok := filter["identification"]; ok {
		object, ok := raw.(map[string]any)
		if !ok {
			return "", validationError("unsupported History filter")
		}
		for key := range object {
			if key != "risk_bands" && key != "hre_min_accounts" && key != "hre_min_devices" {
				return "", validationError("search does not accept ids, device_id_source or chips")
			}
		}
	}
	if raw, ok := filter["entity"]; ok {
		object, ok := raw.(map[string]any)
		if !ok {
			return "", validationError("unsupported entity filter")
		}
		for key := range object {
			if key != "ids" && key != "risk_bands" {
				return "", validationError("unsupported entity filter")
			}
		}
	}
	encoded, err := json.Marshal(filter)
	if err != nil {
		return "", validationError("unsupported History filter")
	}
	return string(encoded), nil
}

func normalizeEntityID(resource, id string) (string, error) {
	if id == "" || len(id) > 512 || strings.ContainsAny(id, "/\\") || id == "." || id == ".." || !utf8.ValidString(id) {
		return "", validationError("invalid entity id")
	}
	for _, r := range id {
		if r < 32 || r == 127 {
			return "", validationError("invalid entity id")
		}
	}
	switch resource {
	case "ip":
		addr, err := netip.ParseAddr(id)
		if err != nil {
			return "", validationError("invalid IP entity id")
		}
		if addr.Is6() {
			mapped := addr.Unmap()
			if !mapped.Is4() {
				return "", validationError("pure IPv6 is not supported by History")
			}
			return mapped.String(), nil
		}
		if !addr.Is4() {
			return "", validationError("invalid IP entity id")
		}
		return addr.String(), nil
	case "identifications", "visitor", "device":
		if !uuidRE.MatchString(id) {
			return "", validationError("this entity id must be a UUID")
		}
		return strings.ToLower(id), nil
	default:
		return id, nil
	}
}

func parseEntityPage(resp *apiResponse) (*EntityPage, error) {
	body, err := decodeObject(resp)
	if err != nil {
		return nil, err
	}
	rows, ok := body["data"].([]any)
	token, tokenOK := body["next_page_token"]
	if !ok || !tokenOK {
		return nil, invalidEntity(resp)
	}
	var next *string
	switch value := token.(type) {
	case nil:
	case string:
		next = &value
	default:
		return nil, invalidEntity(resp)
	}
	if total, present := body["total"]; present {
		if _, ok := asNonNegativeInt(total); !ok {
			return nil, invalidEntity(resp)
		}
	}
	page := &EntityPage{Data: make([]map[string]any, 0, len(rows)), NextPageToken: next}
	for _, row := range rows {
		entity, err := parseEntity(row)
		if err != nil {
			return nil, invalidEntity(resp)
		}
		page.Data = append(page.Data, entity)
	}
	return page, nil
}

func parseEntity(value any) (map[string]any, error) {
	entity, ok := value.(map[string]any)
	if !ok || !oneOf(entity["type"], "identification", "user", "visitor", "device", "ip") {
		return nil, errInvalidEntity
	}
	id, _ := entity["id"].(string)
	domainID, _ := entity["domain_id"].(string)
	domain, _ := entity["domain"].(string)
	if id == "" || !uuidRE.MatchString(domainID) || domain == "" {
		return nil, errInvalidEntity
	}
	if err := validateEntityRisk(entity["risk"], entity["type"].(string)); err != nil {
		return nil, err
	}
	if err := validateEntitySignals(entity["signals"]); err != nil {
		return nil, err
	}
	if count, present := entity["identifications"]; present && count != nil {
		if _, ok := asNonNegativeInt(count); !ok {
			return nil, errInvalidEntity
		}
	}
	return entity, nil
}

func validateEntityRisk(value any, entityType string) error {
	risk, ok := value.(map[string]any)
	if !ok {
		return errInvalidEntity
	}
	if risk["state"] == "ok" {
		if !oneOf(risk["band"], "trusted", "suspicious", "dangerous") {
			return errInvalidEntity
		}
		asOf, _ := risk["as_of"].(string)
		if _, err := time.Parse(time.RFC3339, asOf); err != nil {
			return errInvalidEntity
		}
		if score, present := risk["score"]; present {
			parsed, ok := asNonNegativeInt(score)
			if !ok || parsed > 100 {
				return errInvalidEntity
			}
		} else if entityType == "identification" {
			return errInvalidEntity
		}
		return nil
	}
	if risk["state"] != "unavailable" || risk["band"] != nil || risk["as_of"] != nil {
		return errInvalidEntity
	}
	if _, present := risk["score"]; present {
		return errInvalidEntity
	}
	return nil
}

func validateEntitySignals(value any) error {
	signals, ok := value.(map[string]any)
	if !ok || (signals["state"] != "ok" && signals["state"] != "unavailable") {
		return errInvalidEntity
	}
	items, ok := signals["items"].([]any)
	if !ok {
		return errInvalidEntity
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return errInvalidEntity
		}
	}
	return nil
}

func checkEntityPage(page *EntityPage, domain, resource string, limit int) error {
	if len(page.Data) > limit {
		return errInvalidEntity
	}
	for _, row := range page.Data {
		if !entityMatches(row, domain, resource, "") {
			return errInvalidEntity
		}
	}
	return nil
}

func entityMatches(entity map[string]any, domain, resource, id string) bool {
	expected := resource
	if resource == "identifications" {
		expected = "identification"
	}
	domainID, _ := entity["domain_id"].(string)
	if !strings.EqualFold(domainID, domain) || entity["type"] != expected {
		return false
	}
	if id != "" && entity["id"] != id {
		return false
	}
	return true
}

func decodeObject(resp *apiResponse) (map[string]any, error) {
	var body map[string]any
	if err := json.Unmarshal(resp.body, &body); err != nil || body == nil {
		return nil, invalidEntity(resp)
	}
	return body, nil
}

func invalidEntity(resp *apiResponse) error {
	return &APIError{
		StatusCode: resp.status,
		Message:    "the History API returned an invalid entity response",
		Body:       resp.body,
		Header:     resp.header,
	}
}

func asNonNegativeInt(value any) (int, bool) {
	switch n := value.(type) {
	case float64:
		if n < 0 || n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, n >= 0
	default:
		return 0, false
	}
}

func oneOf(value any, allowed ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, item := range allowed {
		if text == item {
			return true
		}
	}
	return false
}
