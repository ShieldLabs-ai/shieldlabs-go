package shieldlabs

import (
	"fmt"
	"runtime"
)

// Version is the version of this module.
const Version = "1.0.0"

const (
	// DefaultBaseURL is the origin of the History API. Request paths start
	// with /api/v1/history.
	DefaultBaseURL = "https://account.shieldlabs.ai"

	// DefaultManagementBaseURL is the origin of the Management API. Request
	// paths start with /v1.
	DefaultManagementBaseURL = "https://api.shieldlabs.ai"

	// NilUUID is the all-zero UUID. As a device ID it means that the
	// identification had no usable device signals; ban marker rows also use it
	// for other identifiers.
	NilUUID = "00000000-0000-0000-0000-000000000000"
)

// userAgent is sent with every request, for example
// "shieldlabs-go/1.0.0 (go1.24.1; linux/amd64)".
func userAgent() string {
	return fmt.Sprintf("shieldlabs-go/%s (%s; %s/%s)", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
