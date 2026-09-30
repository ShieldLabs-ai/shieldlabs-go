package shieldlabs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Sentinel errors. Match them with [errors.Is]:
//
//	if errors.Is(err, shieldlabs.ErrRateLimited) { ... }
//
// ErrBadRequest, ErrAuthentication, ErrQuotaExceeded, ErrNotFound,
// ErrRateLimited and ErrServer match an *[APIError] with the corresponding
// HTTP status. ErrConnection and ErrTimeout wrap network failures, and
// ErrValidation reports an invalid argument detected before any request was
// sent.
var (
	// ErrValidation reports an invalid argument. Nothing was sent.
	ErrValidation = errors.New("shieldlabs: invalid argument")

	// ErrBadRequest matches HTTP 400.
	ErrBadRequest = errors.New("shieldlabs: bad request")

	// ErrAuthentication matches HTTP 401 and 403: a missing, wrong or
	// disabled key, or a domain that does not match the key.
	ErrAuthentication = errors.New("shieldlabs: authentication failed")

	// ErrQuotaExceeded matches HTTP 402: the account has no requests left.
	ErrQuotaExceeded = errors.New("shieldlabs: quota exceeded")

	// ErrNotFound matches HTTP 404: an unknown route. An identification that
	// has not been found is not an error (see IdentificationsService.Get).
	ErrNotFound = errors.New("shieldlabs: not found")

	// ErrRateLimited matches HTTP 429. APIError.RetryAfter holds the
	// Retry-After delay when the server sent one.
	ErrRateLimited = errors.New("shieldlabs: rate limited")

	// ErrServer matches HTTP 5xx.
	ErrServer = errors.New("shieldlabs: server error")

	// ErrConnection reports a network failure: the request did not reach
	// ShieldLabs or the connection broke before a full response arrived.
	ErrConnection = errors.New("shieldlabs: connection failed")

	// ErrTimeout reports that an HTTP attempt ran out of time without a
	// response.
	ErrTimeout = errors.New("shieldlabs: request timed out")
)

// APIError is returned when a ShieldLabs API answers with an error status, or
// with a response body the SDK cannot read. It matches the sentinel for its
// status code with [errors.Is].
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Message is the error message parsed from the body: the "error" field of
	// a JSON object, a bare JSON string, or a short plain-text body. It is ""
	// when the body carries no message.
	Message string
	// Body is the raw response body.
	Body []byte
	// Header holds the response headers.
	Header http.Header
	// RetryAfter is the delay the Retry-After header asks for, given in
	// seconds or as an HTTP date. It is 0 when the header is absent or
	// invalid, and when it asks for no delay: 0 or a date in the past.
	RetryAfter time.Duration

	// retryAfterSent reports a valid Retry-After header, so that a RetryAfter
	// of 0 asks for an immediate retry instead of meaning "no header".
	retryAfterSent bool
}

// Error returns a one-line description, for example
// "shieldlabs: HTTP 429 Too Many Requests: too many requests".
func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("shieldlabs: HTTP ")
	b.WriteString(strconv.Itoa(e.StatusCode))
	if text := http.StatusText(e.StatusCode); text != "" {
		b.WriteString(" ")
		b.WriteString(text)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// Is reports whether target is the sentinel error for e's status code.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrBadRequest:
		return e.StatusCode == http.StatusBadRequest
	case ErrAuthentication:
		return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
	case ErrQuotaExceeded:
		return e.StatusCode == http.StatusPaymentRequired
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests
	case ErrServer:
		return e.StatusCode >= 500 && e.StatusCode <= 599
	}
	return false
}

// newAPIError builds an APIError from a response. It never fails: error
// bodies are not uniform (empty, JSON null, a bare JSON string, an object,
// plain text or HTML).
func newAPIError(status int, header http.Header, body []byte, now time.Time) *APIError {
	e := &APIError{
		StatusCode: status,
		Message:    errorMessage(body),
		Body:       body,
		Header:     header,
	}
	if header != nil {
		e.RetryAfter, e.retryAfterSent = parseRetryAfter(header.Get("Retry-After"), now)
	}
	return e
}

const maxPlainTextMessage = 200

// errorMessage extracts a human-readable message from an error body.
func errorMessage(body []byte) string {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		switch x := v.(type) {
		case map[string]any:
			for _, key := range []string{"error", "message"} {
				if s, ok := x[key].(string); ok && s != "" {
					return s
				}
			}
		case string:
			return x
		}
		return ""
	}
	s := string(b)
	if strings.HasPrefix(s, "<") || !utf8.ValidString(s) {
		return "" // markup from a proxy, or binary data
	}
	if len(s) > maxPlainTextMessage {
		cut := maxPlainTextMessage
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}

// delaySecondsRE matches a Retry-After delay in seconds: digits with an
// optional fractional part, without a sign or an exponent.
var delaySecondsRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// parseRetryAfter reads a Retry-After value in seconds (integer or decimal)
// or as an HTTP date. ok reports a valid value; then a delay of 0 (for "0" or
// a date that is not in the future) asks for no delay. An absent or invalid
// value, such as a negative number, returns (0, false). Delays too long for a
// time.Duration (about 292 years) saturate, like time.Time.Sub.
func parseRetryAfter(value string, now time.Time) (delay time.Duration, ok bool) {
	value = strings.TrimSpace(value)
	if delaySecondsRE.MatchString(value) {
		// Only digits: ParseFloat can at most overflow to +Inf, which
		// saturates below.
		secs, _ := strconv.ParseFloat(value, 64)
		if secs >= float64(math.MaxInt64/int64(time.Second)) {
			return math.MaxInt64, true
		}
		return time.Duration(secs * float64(time.Second)), true
	}
	if value == "" {
		return 0, false
	}
	if t, err := http.ParseTime(value); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// validationError returns an error that matches ErrValidation.
func validationError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}

// isTransient reports whether a failed call may succeed when repeated.
func isTransient(err error) bool {
	return errors.Is(err, ErrRateLimited) || errors.Is(err, ErrServer) ||
		errors.Is(err, ErrConnection) || errors.Is(err, ErrTimeout)
}
