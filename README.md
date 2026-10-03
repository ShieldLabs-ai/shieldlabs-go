# ShieldLabs Go SDK

Read ShieldLabs identification verdicts, verify webhooks and apply risk checks from your Go backend.

[![CI](https://github.com/ShieldLabs-ai/shieldlabs-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ShieldLabs-ai/shieldlabs-go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/ShieldLabs-ai/shieldlabs-go.svg)](https://pkg.go.dev/github.com/ShieldLabs-ai/shieldlabs-go)
[![Version](https://img.shields.io/github/v/tag/ShieldLabs-ai/shieldlabs-go?label=version&sort=semver)](https://github.com/ShieldLabs-ai/shieldlabs-go/tags)

## How it fits

A ShieldLabs integration always has three steps:

1. **Browser.** The ShieldLabs agent runs an identification and gives your page a request ID. The browser never sees a Risk Score or a device ID.
2. **Your backend.** It receives the request ID together with the protected action (signup, login, checkout) and reads the verdict for it with this SDK, from the History API or from a signed webhook.
3. **Decision.** Your backend acts on the Risk Score, the risk band, the detection flags and the identifiers, for example how many accounts one device ID already has.

This module covers steps 2 and 3. For step 1, see the browser SDKs and the [documentation](https://docs.shieldlabs.ai). New to ShieldLabs? [Start free](https://app.shieldlabs.ai).

## Install

```sh
go get github.com/ShieldLabs-ai/shieldlabs-go
```

Go 1.23 or later. The module uses only the standard library.

## Quick start

Read the identification for a request ID, then evaluate it before creating the account:

```go
package main

import (
	"context"
	"log"
	"os"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
)

func main() {
	client, err := shieldlabs.NewClient(os.Getenv("SHIELDLABS_API_KEY")) // sec_your_private_key
	if err != nil {
		log.Fatal(err)
	}

	// requestID arrives from your page together with the signup form.
	requestID := "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"

	// Waits for the verdict with a 10-second budget; nil means "not scored in time".
	ident, err := client.Identifications.Get(context.Background(), requestID, nil)
	if err != nil {
		log.Fatal(err)
	}

	verdict := shieldlabs.EvaluateIdentification(ident, shieldlabs.EvaluateOptions{
		IsReplay: func(requestID string) bool { return alreadyUsed(requestID) },
	})
	if !verdict.OK {
		log.Printf("signup refused: %s", verdict.Reason) // missing, replayed, stale, blocked_band, ...
		return
	}
	log.Printf("signup allowed: risk score %d (%s)", ident.RiskScore, verdict.Band)
}

// alreadyUsed records the request ID in your store and reports whether it was
// there before. One identification authorizes one protected action.
func alreadyUsed(requestID string) bool { return false }
```

Verify and parse webhook deliveries:

```go
package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ShieldLabs-ai/shieldlabs-go/webhook"
)

func main() {
	http.HandleFunc("POST /webhooks/shieldlabs", handleWebhook)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read the body", http.StatusBadRequest)
		return
	}
	event, err := webhook.ConstructEvent(body, r.Header.Get(webhook.SignatureHeader),
		os.Getenv("SHIELDLABS_WEBHOOK_SECRET")) // whsec_your_signing_secret
	if errors.Is(err, webhook.ErrSignature) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if e, ok := event.(*webhook.IdentificationScoredEvent); ok {
		// Keep this idempotent on the request ID: a later server release
		// retries failed deliveries with identical bytes.
		log.Printf("request %s scored %d (%s)", e.Data.RequestID, e.Data.RiskScore, e.Data.Band())
	}
	w.WriteHeader(http.StatusOK) // answer within one second
}
```

[`examples/nethttp`](./examples/nethttp) is a complete `net/http` server with a guarded `POST /signup` and a `POST /webhooks/shieldlabs` receiver.

## Guide

### Credentials

| Variable | Credential | Used by |
|---|---|---|
| `SHIELDLABS_API_KEY` | Private API Key (`sec_...`), one per domain | `NewClient` (History API) |
| `SHIELDLABS_SECRET_KEY` and `SHIELDLABS_DOMAIN` | Secret Key and the registered domain | `NewManagementClient` (Management API) |
| `SHIELDLABS_WEBHOOK_SECRET` | Endpoint signing secret (`whsec_...`) | `webhook.VerifySignature`, `webhook.ConstructEvent` |
| `SHIELDLABS_API_BASE_URL`, `SHIELDLABS_MANAGEMENT_BASE_URL` | Optional origin overrides for development and tests | pass them to `WithBaseURL`; an empty value keeps the default |

Keys stay on your server. The SDK reads no environment variables itself: pass values explicitly.

### Waiting for the verdict

Scoring is asynchronous. The History row for a request ID appears about 1 to 3 seconds after the browser call, and follow-up checks can refine it for up to about 10 seconds. Start the identification in the browser when the user begins the action (for example when the signup form opens), not when the form is submitted, so that the verdict is usually ready when your backend asks for it. `Identifications.Get` waits for the row:

```go
ident, err := client.Identifications.Get(ctx, requestID, &shieldlabs.GetIdentificationOptions{
	Timeout: 5 * time.Second, // total budget of the wait, default 10 s
})
```

- **Total budget.** `Timeout` (default 10 seconds) bounds the whole wait. `Timeout: 0` means the default 10 seconds, not a zero budget, so a nil options pointer and the zero value both wait with the defaults. `NoWait: true` makes a single lookup instead, retried like any History request.
- **Schedule.** It looks up the request ID at once, then again after waits of 250 ms, 500 ms, 1 s, 1.5 s and then every 2 s. For a `PollInterval` p the waits are p, 2p, 4p, 6p and then 8p, each capped at 2 seconds, or at p when p is longer: 1 s waits 1 s and then every 2 s, and 3 s looks up every 3 s. A `PollInterval` below 100 ms is raised to 100 ms, a guard against unit mistakes (`PollInterval: 250` is 250 ns, not 250 ms).
- **Last lookup at the deadline.** A wait that would end after the deadline is shortened, so the last lookup runs at the deadline.
- **One attempt per lookup.** Each lookup is a single HTTP attempt without the client's retries, with an attempt timeout of `min(client timeout, max(time left, 1 s))`. The lookup at the deadline still gets one second to answer, so `Get` can return up to one second after `Timeout`.
- **Transient errors keep polling.** A 429 or 5xx answer, a network failure or an attempt timeout does not end the wait: the next lookup follows on the schedule.
- **429 floor.** After a 429 the next wait is the longest of the scheduled wait, 1 second and the `Retry-After` delay capped at 10 seconds. Without the header, and with `Retry-After: 0` or a date in the past, the delay counts as 0 and the 1-second floor still applies. Near the deadline that wait is shortened like any other, so the last lookup still runs at the deadline. When the capped `Retry-After` delay alone would end after the deadline, the 429 error is returned at once.
- **4xx stop.** A 400, 401, 403 or 404 answer ends the wait at once with its error (`ErrBadRequest`, `ErrAuthentication` or `ErrNotFound`), because a wrong key or a wrong base URL does not heal.
- **Result.** When the time is up, `Get` returns the error of the last lookup if it failed, otherwise `(nil, nil)`. A missing identification means **unverified**, never clean.
- **First version.** `Get` returns the first version of the row. For the refined state (for example in a later review job), read the row again with `client.History.Search(ctx, shieldlabs.LookupRequestID, requestID, &shieldlabs.HistorySearchOptions{Limit: 1})`.

### Checking an identification before a protected action

`EvaluateIdentification` is a reusable guard. It never performs I/O and checks, in order:

| Reason | Refused when |
|---|---|
| `missing` | the identification is nil |
| `replayed` | your `IsReplay` callback reports the request ID as already used |
| `stale` | it is older than `MaxAge` (default 5 minutes, by `ObservedAt`) |
| `rate_limited` | the Risk Score is the rate-limit marker (above 100, in practice 999): ShieldLabs writes one such identification when a visitor IP goes over the identification rate limit, and request IDs issued while that IP is blocked get no identification at all (`missing`) |
| `no_device_signals` | the device ID is the nil UUID `00000000-0000-0000-0000-000000000000` |
| `blocked_flag` | a flag in `BlockFlags` is set (default `browser_automation`, `javascript_disabled`) |
| `blocked_band` | the band is in `BlockBands` (default `dangerous`) |

The defaults are a starting point: tune them for your traffic. Nil `BlockFlags` or `BlockBands` select the defaults, an empty slice blocks nothing. The SDK stores no state: `IsReplay` should record each request ID atomically in your own store (a database table or a cache with expiry) and return true when it was already there.

Risk bands are computed on the client: **trusted** 0-29, **suspicious** 30-59, **dangerous** 60-100. `RiskBand(score)` returns `BandRateLimited` for scores above 100, and `IsRateLimited(score)` reports the marker. Branch on `RiskScore`, the band and `DetectionFlags`; use `Signals` (the weighted risk signals behind the score) for display and logging. Weights can be negative, so never add them up yourself.

### Searching history for account-abuse checks

The History API returns the identifications that match one identifier, newest first. Search by device ID to count accounts on one device, by User HID to see the devices and countries of one account, or by visitor ID or IP address:

```go
// The nil device ID means "no usable device signals" and matches unrelated
// identifications, so only count accounts for a real device ID.
if ident.DeviceID != shieldlabs.NilUUID {
	page, err := client.History.Search(ctx, shieldlabs.LookupDeviceID, ident.DeviceID,
		&shieldlabs.HistorySearchOptions{Limit: 100})
	if err != nil {
		return err
	}
	accounts := map[string]bool{}
	for _, h := range page.Data {
		// AccountUserHID skips a missing User HID and the values that name
		// no account: "anonymous", "fail", "-1" and "unknown".
		if hid, ok := h.AccountUserHID(); ok {
			accounts[hid] = true
		}
	}
	if len(accounts) >= 3 {
		// several accounts share this device: review the signup
	}
}
```

`IsSentinelUserHID(s)` makes the same check for a plain string.

`History.All` iterates over every page and skips rows it has already yielded (rows can shift between pages while new identifications arrive):

```go
for h, err := range client.History.All(ctx, shieldlabs.LookupUserHID, userHID,
	&shieldlabs.HistoryIterateOptions{MaxItems: 1000}) {
	if err != nil {
		return err
	}
	fmt.Println(h.ObservedAt, h.DeviceID, h.PublicIP.Country)
}
```

`MaxItems` stops the iteration after that many identifications. `MaxItems: 0`, the zero value, means no limit, so a nil options pointer iterates over every row.

Arguments are validated on the client before anything is sent, so a typo never turns into an unfiltered or failing query: the lookup type must be one of `LookupIP`, `LookupUserHID`, `LookupVisitorID`, `LookupRequestID`, `LookupDeviceID`, `LookupSessionID`, `LookupCookieID`; UUIDs must be UUIDs (sent lowercase); an IP must be a dotted IPv4 address; `Limit` is 1 to 100 (0 selects 20) and `Offset` is 0 or more. Invalid arguments return an error matching `ErrValidation`.

A User HID is matched exactly and case-sensitively. It is sent as one path segment in the escaped form the History API decodes, so values with `@`, `+`, `=`, `,`, `;` or spaces match as they are. A User HID that is empty, contains `/`, is `.` or `..`, or is not valid UTF-8 cannot be matched in the request path, so `Search` and `All` return `ErrValidation` for it instead of an empty page. User HIDs from `UserHID` are 64 hex characters and always work; if you build User HIDs another way, avoid `/` (standard base64 contains it, base64url does not).

Country values are English country names such as `"Germany"`, or `""` when unknown.

### Webhooks

ShieldLabs posts `identification.scored` events to your endpoints, signed with `X-Shield-Signature: sha256=<hex HMAC-SHA256 of the raw body>`. The key is the full signing secret including its `whsec_` prefix.

- Verify the **raw** body: read it with `io.ReadAll` and pass the bytes. Parsing and re-encoding the JSON changes them.
- `ConstructEvent` returns `*IdentificationScoredEvent` (with `Data`, a normalized `Identification`), `*PingEvent` (sent by the analytics dashboard's "Verify" button) or `*UnknownEvent` for event types this version does not know. Acknowledge them all.
- Today ShieldLabs sends one delivery per identification and endpoint, with a 1-second timeout and no retries. Answer with a 2xx status within one second and do slow work afterwards or in a queue.
- Make the handler idempotent on `Data.RequestID`: a later server release retries failed deliveries, and a retry resends identical bytes.
- Use the History API for guaranteed reads and for the latest state: a failed delivery is not sent again, and a History row can be refined after its webhook was sent.
- To rotate a secret without downtime, pass both secrets: `webhook.ConstructEvent(body, header, newSecret, oldSecret)`.

The analytics dashboard "Test" button sends a sample `identification.scored` event with 17 of the 19 detection flags; missing flags are parsed as `false`.

### User HID

Link identifications to your accounts with a User HID: a hashed or pseudonymous account ID that you pass to the browser agent. Never pass a raw email address or database ID. `UserHID` computes a stable, irreversible value on your server:

```go
// userHIDSecret is a secret of your own that never reaches the browser.
hid, err := shieldlabs.UserHID(user.ID, userHIDSecret) // 64 lowercase hex characters
```

### Management profile

```go
mgmt, err := shieldlabs.NewManagementClient(os.Getenv("SHIELDLABS_SECRET_KEY"), os.Getenv("SHIELDLABS_DOMAIN"))
if err != nil {
	return err
}
profile, err := mgmt.GetProfile(ctx)
if err != nil {
	return err
}
fmt.Println(profile.Domain, profile.RemainingIdentifications, profile.CreatedAt)
```

The domain is normalized before it is sent (`"https://www.Example.com/"` becomes `"example.com"`), because the API matches the registered domain exactly. `RemainingIdentifications` can be negative when the account is over its included volume. Cache the profile: see the rate limits below.

### Rate limits

| API | Limit | What the SDK does |
|---|---|---|
| History API | about 15 requests per second **per domain**, shared by all your servers | Inside the wait of `Identifications.Get`, a 429 waits at least one second before the next lookup, longer when the scheduled wait or `Retry-After` (up to 10 seconds) asks for more. Ordinary calls (`Search`, `All` and a `NoWait` lookup) follow `Retry-After` as sent, up to 10 seconds (`Retry-After: 0` or a date in the past retries at once), and retry a 429 without `Retry-After` after at least one second |
| Management API | about 15 requests per minute **per caller IP**, then that IP is blocked for 10 minutes | never retries a 429, because a retry only runs into the block |

A waiting `Identifications.Get` makes at most 9 lookups in its default 10-second wait (4 in the first 2 seconds, then one every 2 seconds and the last one at the deadline) and usually far fewer, because the row appears about 1 to 3 seconds after the browser call. Starting the identification early keeps that number low. Call the Management API sparingly and cache its answers.

### Configuration and concurrency

```go
client, err := shieldlabs.NewClient(apiKey,
	shieldlabs.WithBaseURL(os.Getenv("SHIELDLABS_API_BASE_URL")), // empty keeps https://account.shieldlabs.ai
	shieldlabs.WithHTTPClient(&http.Client{Transport: myTransport}),
	shieldlabs.WithTimeout(5*time.Second),                        // per HTTP attempt, default 10 s
	shieldlabs.WithMaxRetries(3),                                 // default 2
	shieldlabs.WithLogger(slog.Default()),                        // configuration warnings only
)
```

The History base URL is the origin; request paths start with `/api/v1/history`, and a trailing `/api` on the base URL is removed. The Management API origin is `https://api.shieldlabs.ai`. Base URLs must use https, because every request carries a key. Plain http is accepted for `localhost`, `127.0.0.0/8` and `[::1]` (local mock servers); `WithInsecureHTTP()` allows it for a test server on another host and logs a warning. Keys, secrets and domains that contain whitespace or control characters (a bad copy and paste) are rejected with `ErrValidation`.

Every client method takes a `context.Context` for cancellation and deadlines. Clients are safe for concurrent use by multiple goroutines: create one per key and reuse it. The SDK sends `Authorization`, `Accept: application/json` and `User-Agent: shieldlabs-go/<version>`, collects no telemetry and never logs keys, secrets or response bodies.

## Reference

Full documentation: [pkg.go.dev](https://pkg.go.dev/github.com/ShieldLabs-ai/shieldlabs-go) and [docs.shieldlabs.ai](https://docs.shieldlabs.ai).

| API | Description |
|---|---|
| `NewClient(apiKey, ...Option) (*Client, error)` | History API client (Private API Key) |
| `WithBaseURL`, `WithHTTPClient`, `WithTimeout`, `WithMaxRetries`, `WithLogger`, `WithInsecureHTTP` | Options for both clients |
| `(*IdentificationsService).Get(ctx, requestID, *GetIdentificationOptions) (*Identification, error)` | One identification by request ID, waiting for the verdict unless `NoWait` is set; `(nil, nil)` when not found in time |
| `GetIdentificationOptions{NoWait, Timeout, PollInterval}` | The zero value waits: `Timeout` 0 means 10 s, `PollInterval` 0 means 250 ms (values below 100 ms become 100 ms); waits are p, 2p, 4p, 6p, then 8p, each capped at max(2 s, p) |
| `(*HistoryService).Search(ctx, LookupType, value, *HistorySearchOptions) (*HistoryPage, error)` | One page of identifications for an identifier |
| `(*HistoryService).All(ctx, LookupType, value, *HistoryIterateOptions) iter.Seq2[*Identification, error]` | Iterator over every page, deduplicated on request ID |
| `HistorySearchOptions{Limit, Offset}`, `HistoryIterateOptions{PageSize, MaxItems}` | `Limit` 0 means 20, `PageSize` 0 means 100, `MaxItems` 0 means no limit |
| `NewManagementClient(secretKey, domain, ...Option) (*ManagementClient, error)` | Management API client (Secret Key and domain) |
| `(*ManagementClient).GetProfile(ctx) (*DomainProfile, error)` | Domain profile |
| `webhook.VerifySignature(payload, header, ...secrets) bool` | Constant-time signature check, one or more secrets |
| `webhook.ConstructEvent(payload, header, ...secrets) (webhook.Event, error)` | Verified, typed event |
| `EvaluateIdentification(*Identification, EvaluateOptions) Evaluation` | Guard policy with a refusal reason |
| `RiskBand(score) Band`, `IsRateLimited(score) bool` | Band helpers |
| `UserHID(userID, secret) (string, error)` | HMAC-SHA256 User HID |
| `(*Identification).AccountUserHID() (string, bool)`, `IsSentinelUserHID(s) bool` | Skip User HID values that name no account when counting accounts |
| `ParseHistoryRow([]byte)`, `ParseWebhookData([]byte)` | Normalize a History row or webhook data into an `Identification` |
| `SignalSlug(description) string` | Signal name for a History signal description |
| `Identification`, `DetectionFlags`, `Signal`, `IPInfo`, `TrafficSource`, `DomainProfile`, `HistoryPage` | Data model; JSON field names follow the webhook contract |

`Identification` fields: `RequestID`, `VisitorID`, `DeviceID`, `SessionID`, `CookieID`, `UserHID` (nil when none), `Domain`, `PublicIP`, `LocalIP` (each `{IP, Country}`), `ConnectionType` (`direct`, `mobile`, `vpn`, `proxy`, `tor`, `privacy_relay`, `browser_vpn_proxy`, `unknown`), `OS`, `Browser`, `DeviceType`, `TrafficSource`, `RiskScore`, `Signals`, `DetectionFlags` (19 booleans), `ObservedAt` (UTC), `Source` (`webhook` or `history`) and `Raw` (the original object). Unknown values are kept as they arrive.

## Errors and retries

Errors work with `errors.Is` and `errors.As`:

| Condition | Match with | Retried |
|---|---|---|
| Invalid argument, nothing sent | `ErrValidation` | no |
| HTTP 400 | `ErrBadRequest` | no |
| HTTP 401, 403 (wrong or disabled key, wrong domain) | `ErrAuthentication` | no |
| HTTP 402 (no requests left on the account) | `ErrQuotaExceeded` | no |
| HTTP 404 (unknown route) | `ErrNotFound` | no |
| HTTP 429 | `ErrRateLimited`, `APIError.RetryAfter` | History: yes; Management: never |
| HTTP 5xx | `ErrServer` | yes |
| Network failure | `ErrConnection` | yes |
| No response within the attempt timeout | `ErrTimeout` | yes |
| Invalid webhook signature | `webhook.ErrSignature` | not applicable |
| Signed but invalid webhook body | `webhook.ErrParse` | not applicable |

Every HTTP error is an `*APIError` with `StatusCode`, `Message` (parsed from the body), `Body`, `Header` and `RetryAfter` (the delay the `Retry-After` header asks for, in seconds or as an HTTP date; 0 when the header is absent, invalid, 0 or a date in the past):

```go
var apiErr *shieldlabs.APIError
if errors.As(err, &apiErr) {
	log.Printf("ShieldLabs answered %d: %s", apiErr.StatusCode, apiErr.Message)
}
```

Only GET requests are sent, and failed attempts are retried up to `WithMaxRetries` times (default 2) with exponential backoff (0.5 s doubling up to 8 s, randomized) or the delay the server's `Retry-After` asks for, as sent (capped at 10 s): `Retry-After: 0` or a date in the past retries at once. A 429 without a valid `Retry-After` waits at least 1 s, because the History limit counts requests per one-second window. The lookups of a waiting `Identifications.Get` are single attempts: instead of retrying, the wait looks up again on its schedule (see [Waiting for the verdict](#waiting-for-the-verdict)). A cancelled or expired context stops at once and matches `context.Canceled` or `context.DeadlineExceeded`.

## Compatibility

- Go 1.23 or later (the History iterator uses range-over-func). CI runs Go 1.23, 1.24, 1.25 and the two current stable releases.
- Standard library only, no third-party dependencies.
- Webhook schema version `2026-06-01`. Unknown fields, flags, connection types, risk signals, event types and schema versions are tolerated.
- Semantic versioning: breaking changes only in a new major version.

## Development

The supported client consumes typed wire views generated from the checked-in OpenAPI description.
History queries, profile headers and response normalization use these views directly: renaming a
consumed field or changing its type makes the client fail compilation. Unknown fields and string
values, nulls and malformed historical values still follow the existing tolerant normalization;
`Raw` retains the original decoded object. The public API, HTTP transport and retry logic remain
handwritten. The separate `generated/` reference client is not used at runtime because its strict
decoders reject some values this SDK intentionally tolerates.

```bash
python3 -m pip install -r scripts/requirements.txt  # development only
./sync.sh      # download the current OpenAPI description into resources/
./generate.sh  # rebuild reference client and supported wire views
python3 scripts/generate-contract.py --check
python3 scripts/check-contract-drift.py
python3 scripts/check-consumer.py
```
`python3 scripts/generate-contract.py` rebuilds only the supported views in
`internal/contract/`. Generation uses `gofmt` from the local Go toolchain, or the same
Go 1.24 Docker image used for tests. Python and PyYAML are development tools, not
dependencies of applications using this module.

```sh
# with a local Go toolchain
test -z "$(gofmt -l .)" && go vet ./... && go test -race -cover ./... && go build ./...

# or in Docker
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm \
  sh -c 'test -z "$(gofmt -l .)" && go vet ./... && go test -race -cover ./... && go build ./...'
```

`testdata/` holds the shared test fixtures (History pages, webhook deliveries, signature vectors, error bodies) that every ShieldLabs server SDK passes. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Questions or issues: [contact@shieldlabs.ai](mailto:contact@shieldlabs.ai).

## License

[MIT](./LICENSE)
