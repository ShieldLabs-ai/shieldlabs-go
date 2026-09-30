// Package shieldlabs is the ShieldLabs server SDK for Go.
//
// A ShieldLabs integration has three steps:
//
//  1. In the browser, the ShieldLabs agent runs an identification and hands
//     your page a request ID. The browser never sees a Risk Score or a
//     device ID.
//  2. Your backend receives the request ID together with the protected action
//     (signup, login, checkout) and reads the verdict for it from the History
//     API, or receives the verdict in a signed webhook.
//  3. Your backend decides what to do with the verdict: the Risk Score, the
//     risk band, the detection flags and the identifiers.
//
// This package covers step 2 and helps with step 3:
//
//   - [NewClient] creates a History API client (Private API Key, sec_...).
//     [IdentificationsService.Get] reads the identification for one request
//     ID, waiting until it has been scored. [HistoryService.Search] and
//     [HistoryService.All] read the history of one device, user, visitor, IP
//     address, session or cookie.
//   - [NewManagementClient] creates a Management API client (Secret Key plus
//     registered domain) for [ManagementClient.GetProfile].
//   - The webhook subpackage verifies X-Shield-Signature and parses webhook
//     deliveries into typed events.
//   - [RiskBand], [IsRateLimited], [EvaluateIdentification] and [UserHID] are
//     small, dependency-free helpers.
//
// Webhook deliveries and History rows are normalized into one model,
// [Identification], whose JSON field names follow the webhook contract.
//
// Every client is safe for concurrent use by multiple goroutines. Create one
// client per key and reuse it.
//
// Errors can be inspected with [errors.Is] and [errors.As]: API responses
// with an error status are returned as *[APIError] and match sentinels such
// as [ErrAuthentication] or [ErrRateLimited]; invalid arguments match
// [ErrValidation] and are reported before any request is sent.
package shieldlabs
