package shieldlabs_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	shieldlabs "github.com/ShieldLabs-ai/shieldlabs-go"
)

func ExampleNewClient() {
	client, err := shieldlabs.NewClient("sec_your_private_key")
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

func ExampleIdentificationsService_Get() {
	client, err := shieldlabs.NewClient("sec_your_private_key")
	if err != nil {
		log.Fatal(err)
	}
	// requestID comes from your page, sent together with the protected action.
	requestID := "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"

	ident, err := client.Identifications.Get(context.Background(), requestID, nil)
	if err != nil {
		log.Fatal(err)
	}
	if ident == nil {
		fmt.Println("not scored in time: treat as unverified")
		return
	}
	fmt.Println(ident.RiskScore, ident.Band(), ident.DetectionFlags.VPN)
}

func ExampleHistoryService_Search() {
	client, err := shieldlabs.NewClient("sec_your_private_key")
	if err != nil {
		log.Fatal(err)
	}
	// How many identifications, and how many distinct accounts, has this
	// device? Skip the nil device ID (no usable device signals): it matches
	// unrelated identifications.
	deviceID := "ac7c303d-971b-41d1-8e25-cd5b46b46aed"
	if deviceID == shieldlabs.NilUUID {
		return
	}
	page, err := client.History.Search(context.Background(), shieldlabs.LookupDeviceID, deviceID,
		&shieldlabs.HistorySearchOptions{Limit: 100})
	if err != nil {
		log.Fatal(err)
	}
	accounts := map[string]bool{}
	for _, ident := range page.Data {
		// AccountUserHID skips nil and the values that name no account
		// ("anonymous", "fail", "-1", "unknown").
		if hid, ok := ident.AccountUserHID(); ok {
			accounts[hid] = true
		}
	}
	fmt.Printf("%d identifications, %d accounts on this device\n", page.Total, len(accounts))
}

func ExampleHistoryService_All() {
	client, err := shieldlabs.NewClient("sec_your_private_key")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	for ident, err := range client.History.All(ctx, shieldlabs.LookupUserHID, "9f86d081884c7d659a2feaa0c55ad015",
		&shieldlabs.HistoryIterateOptions{MaxItems: 500}) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ident.ObservedAt.Format(time.RFC3339), ident.DeviceID, ident.PublicIP.Country)
	}
}

func ExampleManagementClient_GetProfile() {
	mgmt, err := shieldlabs.NewManagementClient("your_secret_key", "example.com")
	if err != nil {
		log.Fatal(err)
	}
	// About 15 requests per minute per IP: cache the result.
	profile, err := mgmt.GetProfile(context.Background())
	if errors.Is(err, shieldlabs.ErrRateLimited) {
		log.Fatal("Management API limit reached: wait before calling again")
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(profile.Domain, profile.RemainingIdentifications)
}

func ExampleRiskBand() {
	for _, score := range []int{0, 30, 60, 999} {
		fmt.Println(score, shieldlabs.RiskBand(score))
	}
	// Output:
	// 0 trusted
	// 30 suspicious
	// 60 dangerous
	// 999 rate_limited
}

func ExampleEvaluateIdentification() {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ident := &shieldlabs.Identification{
		RequestID:  "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53",
		DeviceID:   "ac7c303d-971b-41d1-8e25-cd5b46b46aed",
		RiskScore:  65,
		ObservedAt: now.Add(-20 * time.Second),
	}
	used := map[string]bool{}
	verdict := shieldlabs.EvaluateIdentification(ident, shieldlabs.EvaluateOptions{
		Now: now,
		IsReplay: func(requestID string) bool {
			seen := used[requestID]
			used[requestID] = true
			return seen
		},
	})
	fmt.Println(verdict.OK, verdict.Reason, verdict.Band)

	verdict = shieldlabs.EvaluateIdentification(nil, shieldlabs.EvaluateOptions{})
	fmt.Println(verdict.OK, verdict.Reason)
	// Output:
	// false blocked_band dangerous
	// false missing
}

func ExampleUserHID() {
	hid, err := shieldlabs.UserHID("user-42", "server-side-secret")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hid)
	// Output:
	// 7900fe533a0c4a3231be8bf94641b2f0b20bd2af0ef7bf2eadb759233cc3d822
}

func ExampleIsSentinelUserHID() {
	for _, hid := range []string{"9f86d081884c7d659a2feaa0c55ad015", "anonymous", "unknown"} {
		fmt.Println(hid, shieldlabs.IsSentinelUserHID(hid))
	}
	// Output:
	// 9f86d081884c7d659a2feaa0c55ad015 false
	// anonymous true
	// unknown true
}

func ExampleSignalSlug() {
	fmt.Println(shieldlabs.SignalSlug("Is VPN"))
	fmt.Println(shieldlabs.SignalSlug("Antidetect browser (turn_block)"))
	// Output:
	// vpn
	// antidetect_browser
}
