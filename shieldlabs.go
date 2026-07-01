// Package shieldlabs is the ShieldLabs server SDK for Go: API client,
// webhook verification, and types.
//
// It talks to the ShieldLabs API and verifies inbound webhooks. Your code
// decides what to do with the score: you set the rules. This SDK never makes
// the decision for you.
//
// Status: pre-launch scaffold. The surface below is a placeholder and will be
// finalized from the OpenAPI specification before the first release.
package shieldlabs

import "errors"

// ErrNotReady is returned by every method until the first release.
var ErrNotReady = errors.New("shieldlabs-go is not published yet; see https://shieldlabs.ai")

// Client is the ShieldLabs API client.
type Client struct {
	APIKey  string
	BaseURL string
}

// New returns a new ShieldLabs client.
func New(apiKey string) *Client {
	return &Client{APIKey: apiKey}
}

// GetResult fetches a stored identification result by request id. Not implemented yet.
func (c *Client) GetResult(requestID string) (map[string]any, error) {
	return nil, ErrNotReady
}

// VerifyWebhook verifies the signature of an inbound ShieldLabs webhook. Not implemented yet.
func VerifyWebhook(payload []byte, signature, secret string) (bool, error) {
	return false, ErrNotReady
}
