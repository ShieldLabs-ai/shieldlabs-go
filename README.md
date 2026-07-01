# shieldlabs-go

ShieldLabs server SDK for Go: API client, webhook verification, and types.

> **Pre-launch.** This package is a placeholder to reserve the name and shape the public API. It is not published yet and the surface will change. Follow along at [shieldlabs.ai](https://shieldlabs.ai).

Your code decides what to do with the score. This SDK never makes the decision for you. You set the rules.

## Install

```bash
go get github.com/ShieldLabs-ai/shieldlabs-go   # coming soon
```

## Usage (subject to change)

```go
client := shieldlabs.New(os.Getenv("SHIELDLABS_API_KEY"))
ok, _ := shieldlabs.VerifyWebhook(body, signature, secret)
_ = ok
_ = client
```

## About ShieldLabs

ShieldLabs gives you identification and anonymity detection with an explainable risk score (0-100) and detailed signals, so you can assess traffic quality and act on abuse and fraud in your own code. You read the score and its details; your code owns the decision. You set the rules.

- Website: [shieldlabs.ai](https://shieldlabs.ai)
- Get started: [Start Free](https://shieldlabs.ai)

## License

[MIT](./LICENSE)
