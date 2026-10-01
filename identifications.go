package shieldlabs

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const (
	defaultWaitTimeout  = 10 * time.Second
	defaultPollInterval = 250 * time.Millisecond
	// minPollInterval guards against time.Duration unit mistakes: a
	// PollInterval of 250 is 250 ns, not 250 ms.
	minPollInterval = 100 * time.Millisecond
	// pollWaitCap caps every wait between lookups, unless the poll interval
	// is longer: then the interval is the cap.
	pollWaitCap = 2 * time.Second
	// minPollAttemptTimeout is the time a lookup always gets to answer, even
	// when less time is left before the deadline (unless the client timeout
	// is shorter).
	minPollAttemptTimeout = time.Second
)

// pollLadder lists the waits between lookups as multiples of the poll
// interval. The last multiple repeats, and every wait is capped at
// max(pollWaitCap, interval).
var pollLadder = [...]time.Duration{1, 2, 4, 6, 8}

// GetIdentificationOptions controls [IdentificationsService.Get]. The zero
// value, like a nil *GetIdentificationOptions, waits for the verdict with the
// defaults.
type GetIdentificationOptions struct {
	// NoWait makes a single lookup instead of waiting for the verdict. That
	// lookup is retried like any History request, and Timeout and
	// PollInterval do not apply.
	NoWait bool
	// Timeout is the total time budget of the wait. Zero means 10 seconds.
	// The last lookup runs at the deadline and gets at least one second to
	// answer (or the client timeout when that is shorter), so Get can return
	// up to one second after Timeout.
	Timeout time.Duration
	// PollInterval sets the waits between lookups: for an interval p they are
	// p, 2p, 4p, 6p and then 8p, each capped at 2 seconds or at p when p is
	// longer. The default 250 ms gives 250 ms, 500 ms, 1 s, 1.5 s, then 2 s;
	// 1 s gives 1 s, then 2 s; 3 s gives a lookup every 3 s. Zero means
	// 250 ms. Values below 100 ms are raised to 100 ms, a guard against unit
	// mistakes such as PollInterval: 250, which is 250 ns.
	PollInterval time.Duration
}

// IdentificationsService reads single identifications. Get it from
// [Client].Identifications.
type IdentificationsService struct {
	c *Client
}

// Get returns the identification for a request ID, or (nil, nil) when none
// was found in time.
//
// Scoring is asynchronous: the History row appears about 1 to 3 seconds
// after the browser call, and follow-up checks can refine it for up to about
// 10 seconds. Start the identification in the browser when the user begins
// the action (for example when the signup form opens), so that the verdict is
// usually ready when your backend asks for it.
//
// Unless opts.NoWait is set, Get waits for the row, and opts.Timeout (10 s by
// default) is the total budget of the wait. Get looks up the request ID at
// once, then again after waits of 250 ms, 500 ms, 1 s, 1.5 s and then every
// 2 s (p, 2p, 4p, 6p and then 8p for a PollInterval p, each capped at
// max(2 s, p)), and the last lookup runs at the deadline. Each lookup is a
// single HTTP attempt, without the client's retries, and gets min(client
// timeout, max(time left, 1 s)) to answer.
//
// A 429 or 5xx answer, a network failure or an attempt timeout does not end
// the wait: the next lookup follows on the same schedule. The History API
// allows about 15 requests per second per domain for all callers together, so
// after a 429 the next wait is the longest of the scheduled wait, one second
// and the Retry-After delay capped at 10 seconds. Without the header, and
// with "Retry-After: 0" or a date in the past, the delay counts as 0 and the
// one-second minimum still applies. Near the deadline that wait is shortened
// like any other, so that the last lookup runs at the deadline, but when the
// capped Retry-After delay alone would end after the deadline, Get returns
// the 429 error at once.
//
// A 400, 401, 403 or 404 answer ends the wait at once with its error
// ([ErrBadRequest], [ErrAuthentication], [ErrNotFound]), because a wrong key
// or a wrong base URL does not heal, and so does any other answer that
// another lookup cannot change.
//
// When the time is up, Get returns the error of the last lookup if it
// failed, and (nil, nil) otherwise. A nil result means "unverified", never
// "clean": treat it like a failed check. Get returns the first version of the
// row it finds; for the refined state, read the row again later with
// [HistoryService.Search] and [LookupRequestID].
//
// With opts.NoWait, Get makes a single lookup, retried like any History
// request.
//
// The request ID must be a UUID; otherwise the error matches [ErrValidation]
// and nothing is sent.
func (s *IdentificationsService) Get(ctx context.Context, requestID string, opts *GetIdentificationOptions) (*Identification, error) {
	id, err := validateLookup(LookupRequestID, requestID)
	if err != nil {
		return nil, validationError("the request ID must be a UUID, as returned by the browser agent")
	}
	if opts == nil {
		opts = &GetIdentificationOptions{}
	}
	if opts.Timeout < 0 || opts.PollInterval < 0 {
		return nil, validationError("the timeout and the poll interval must not be negative")
	}
	req := historyRequest(LookupRequestID, id, 1, 0)
	if opts.NoWait {
		return s.lookup(ctx, req)
	}
	timeout, interval := defaultWaitTimeout, defaultPollInterval
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}
	if opts.PollInterval > 0 {
		interval = max(opts.PollInterval, minPollInterval)
	}
	return s.poll(ctx, req, timeout, interval)
}

// lookup sends one request for the newest row of a request ID.
func (s *IdentificationsService) lookup(ctx context.Context, req apiRequest) (*Identification, error) {
	page, err := s.c.History.search(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(page.Data) == 0 {
		return nil, nil
	}
	return page.Data[0], nil
}

// poll repeats lookup on the backoff schedule until a row appears or the time
// budget is spent. Each lookup is a single HTTP attempt.
func (s *IdentificationsService) poll(ctx context.Context, req apiRequest, timeout, interval time.Duration) (*Identification, error) {
	clk := s.c.t.clock
	deadline := clk.Now().Add(timeout)
	schedule := newPollSchedule(interval)
	req.once = true
	for {
		req.attemptTimeout = pollAttemptTimeout(s.c.t.timeout, deadline.Sub(clk.Now()))
		ident, err := s.lookup(ctx, req)
		switch {
		case err == nil && ident != nil:
			return ident, nil
		case err != nil && ctx.Err() != nil:
			return nil, err // the caller's context ended
		case err != nil && !isTransient(err):
			return nil, err // 400, 401, 403, 404 and other answers that do not change
		}

		// Nothing found yet, or a 429, a 5xx, a network failure or an attempt
		// timeout. When the time is up, the result of the last lookup stands:
		// its error, or (nil, nil) for "not found in time".
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return nil, err
		}
		wait := schedule.next()
		if delay, limited := rateLimitDelay(err); limited {
			if delay > remaining {
				return nil, err // the Retry-After delay ends after the deadline
			}
			wait = max(wait, minRateLimitDelay, delay)
		}
		// A wait that would end after the deadline is shortened, so that the
		// last lookup runs at the deadline.
		if serr := clk.Sleep(ctx, min(wait, remaining)); serr != nil {
			return nil, contextError(ctx, err)
		}
	}
}

// pollAttemptTimeout returns the timeout of one lookup while waiting: the
// time left before the deadline, at least one second, and never more than the
// client's attempt timeout (0 disables that limit).
func pollAttemptTimeout(clientTimeout, remaining time.Duration) time.Duration {
	d := max(remaining, minPollAttemptTimeout)
	if clientTimeout > 0 {
		d = min(d, clientTimeout)
	}
	return d
}

// rateLimitDelay reports whether err is a 429 answer and returns its
// Retry-After delay capped at 10 seconds. The delay is 0 when the header is
// absent, invalid, 0 or a date in the past.
func rateLimitDelay(err error) (delay time.Duration, limited bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	return min(apiErr.RetryAfter, maxRetryAfter), true
}

// pollSchedule yields the waits between lookups: the poll interval times 1,
// 2, 4, 6 and then 8 for every later wait, each capped at max(2 s,
// interval).
type pollSchedule struct {
	interval time.Duration
	step     int
}

func newPollSchedule(interval time.Duration) *pollSchedule {
	return &pollSchedule{interval: interval}
}

func (p *pollSchedule) next() time.Duration {
	factor := pollLadder[min(p.step, len(pollLadder)-1)]
	p.step++
	if p.interval >= pollWaitCap {
		// The interval is the cap and every multiple is at least 1, so every
		// wait is the interval. Not multiplying also keeps huge intervals from
		// overflowing.
		return p.interval
	}
	return min(factor*p.interval, pollWaitCap)
}
