# Test fixtures

Shared test fixtures that every ShieldLabs server SDK passes. Keep them byte-exact: do not edit
or reformat them by hand.

| File | Content |
|---|---|
| `history-page.json`, `history-empty.json` | History API response bodies (5 rows: dangerous with a paid click, trusted anonymous, VPN with a local network leak and negative signals, the 999 rate-limit marker, a search engine crawler) |
| `normalization-cases.json` | History rows and webhook data objects with the exact `Identification` each must produce |
| `signal-slug-cases.json` | History signal descriptions and their signal names |
| `risk-band-cases.json` | Scores and their risk bands |
| `webhook-identification-scored.json`, `.raw.txt` | A scored event, readable and as the exact bytes sent |
| `webhook-rate-limited.json` | A scored event with the 999 rate-limit marker |
| `webhook-ping.json`, `.raw.txt` | A verification ping, readable and as the exact bytes sent |
| `webhook-test-delivery.json` | The analytics dashboard test delivery (17 of 19 flags, second-precision timestamps) |
| `webhook-signature-vectors.json` | 21 signature vectors with one secret or a list of secrets |
| `management-profile.json`, `management-profile-expected.json` | A Management API profile and its normalized `DomainProfile` |
| `error-responses.json` | Error bodies per API and status, the expected error kind and whether it is retried |
