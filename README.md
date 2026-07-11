# shieldlabs-go

ShieldLabs server SDK for Go: webhook verification, typed events, History API client.

```go
import "github.com/ShieldLabs-ai/shieldlabs-go"

ok := shieldlabs.VerifyWebhook(rawBody, r.Header.Get("X-Shield-Signature"), secret)
```

Signature: `X-Shield-Signature: sha256=` + hex(HMAC-SHA256(secret, raw_body)). Schema `2026-06-01`.

## License

[MIT](./LICENSE)
