# Changelog

All notable changes to this module are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this module follows
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-10-05

### Added

- `sync.sh` downloads the OpenAPI description and `generate.sh` rebuilds the reference client and the typed wire views consumed by the supported SDK.
- History request parameters, profile headers and History/profile/webhook normalization now consume schema-derived types. Public types, raw payloads and tolerant normalization remain compatible.
- Deterministic generation checks, incompatible schema mutation checks and an isolated module-archive consumer check.

## [1.0.0] - 2026-09-30

First stable release. It replaces the preview package (`New`, `GetHistory`, `VerifyWebhook`)
with a new API.

### Added

- `NewClient` for the History API with the options `WithBaseURL`, `WithHTTPClient`,
  `WithTimeout`, `WithMaxRetries`, `WithLogger` and `WithInsecureHTTP`. Base URLs must use
  https; plain http is accepted for `localhost`, `127.0.0.0/8` and `[::1]`, and for other hosts
  only with `WithInsecureHTTP`. `WithBaseURL("")` keeps the default origin.
- `Identifications.Get` reads one identification by request ID and waits for the verdict by
  default: a nil `*GetIdentificationOptions` and its zero value both wait, and `NoWait` makes a
  single lookup. `Timeout` (10 s by default) is the total budget of the wait. It looks up the
  request ID at once, then after 250 ms, 500 ms, 1 s, 1.5 s and every 2 s (p, 2p, 4p, 6p and
  then 8p for a `PollInterval` p, each capped at 2 s or at p when p is longer, so 3 s looks up
  every 3 s; a `PollInterval` below 100 ms is raised to 100 ms), and the last lookup runs at
  the deadline. Each lookup is a single HTTP attempt with a timeout of
  `min(client timeout, max(time left, 1 s))`. A 429 or 5xx answer, a network failure or an
  attempt timeout keeps the wait going.
  After a 429 the next wait is the longest of the scheduled wait, 1 s and `Retry-After` capped
  at 10 s (no header, `Retry-After: 0` and a date in the past count as 0), shortened to the
  deadline; when the capped `Retry-After` alone ends after the deadline, the 429 is returned at
  once. 400, 401, 403 and 404 end the wait at once. When the time is up, `Get` returns the
  error of the last lookup if it failed, and nil otherwise.
- `History.Search` for one page and `History.All`, a range-over-func iterator over every page
  that skips rows it has already yielded.
- Client-side validation of lookup types, UUIDs, IPv4 addresses, User HIDs, limits and offsets
  before any request is sent (`ErrValidation`). User HIDs are sent in the escaped form the
  History API decodes; values that contain `/`, the values `.` and `..`, and invalid UTF-8
  cannot be matched and are rejected.
- Keys, secrets and domains with whitespace or control characters are rejected with
  `ErrValidation` instead of failing later as a connection error.
- `NewManagementClient` and `GetProfile` with domain normalization and a `DomainProfile` model.
- One `Identification` model for webhook data and History rows, with the 19 detection flags,
  risk signals (History descriptions are mapped to the webhook signal names), English country
  names, `ObservedAt` in UTC and the original object in `Raw`.
- `webhook` subpackage: `VerifySignature` and `ConstructEvent` accept one or more signing
  secrets for rotation without downtime, and return typed `IdentificationScoredEvent`,
  `PingEvent` and `UnknownEvent` values. The analytics dashboard test delivery (17 flags)
  parses without errors.
- Risk helpers: `RiskBand` (trusted 0-29, suspicious 30-59, dangerous 60-100, rate-limit
  marker above 100), `IsRateLimited`, `EvaluateIdentification` and `UserHID`.
- `Identification.AccountUserHID` and `IsSentinelUserHID` skip the User HID values that name no
  account (`"anonymous"`, `"fail"`, `"-1"`, `"unknown"`) when counting accounts.
- Error model for `errors.Is` and `errors.As`: `*APIError` plus `ErrBadRequest`,
  `ErrAuthentication`, `ErrQuotaExceeded`, `ErrNotFound`, `ErrRateLimited`, `ErrServer`,
  `ErrConnection`, `ErrTimeout`, `webhook.ErrSignature` and `webhook.ErrParse`.
  `APIError.RetryAfter` holds the delay the `Retry-After` header asks for (seconds or an HTTP
  date), and 0 when the header is absent, invalid, 0 or a date in the past.
- Retries for GET requests on network errors, timeouts, 429 and 5xx with exponential backoff,
  or after the delay `Retry-After` asks for, as sent (capped at 10 s; `Retry-After: 0` or a
  date in the past retries at once). A 429 without `Retry-After` waits at least 1 s. The
  Management client never retries a 429.
- `User-Agent: shieldlabs-go/<version>` header, `context.Context` on every call, clients safe
  for concurrent use.
- `examples/nethttp`: a `net/http` server with a guarded signup and a webhook receiver.

### Changed

- The History base URL is the origin `https://account.shieldlabs.ai`. A trailing `/api` on a
  custom base URL is removed.
- The minimum Go version is 1.23.

### Fixed

- History requests no longer go to `/api/api/v1/history/...`, which answered 404.
