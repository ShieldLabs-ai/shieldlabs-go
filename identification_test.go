package shieldlabs

import "testing"

func TestIsSentinelUserHID(t *testing.T) {
	for _, hid := range []string{"", "anonymous", "fail", "-1", "unknown"} {
		if !IsSentinelUserHID(hid) {
			t.Errorf("IsSentinelUserHID(%q) = false", hid)
		}
	}
	for _, hid := range []string{"9f86d081884c7d659a2feaa0c55ad015", "Anonymous", "UNKNOWN", " fail", "-1 ", "0", "user-42"} {
		if IsSentinelUserHID(hid) {
			t.Errorf("IsSentinelUserHID(%q) = true", hid)
		}
	}
}

func TestAccountUserHID(t *testing.T) {
	tests := []struct {
		userHID *string
		want    string
		ok      bool
	}{
		{nil, "", false},
		{ptr("anonymous"), "", false},
		{ptr("fail"), "", false},
		{ptr("-1"), "", false},
		{ptr("unknown"), "", false},
		{ptr(""), "", false},
		{ptr("9f86d081884c7d659a2feaa0c55ad015"), "9f86d081884c7d659a2feaa0c55ad015", true},
	}
	for _, tc := range tests {
		ident := &Identification{UserHID: tc.userHID}
		got, ok := ident.AccountUserHID()
		if got != tc.want || ok != tc.ok {
			t.Errorf("AccountUserHID(%v) = %q, %v; want %q, %v", tc.userHID, got, ok, tc.want, tc.ok)
		}
	}
}

// TestAccountCountSkipsSentinels counts the accounts on a History page the
// way the README does: sentinel and missing User HIDs are not accounts.
func TestAccountCountSkipsSentinels(t *testing.T) {
	page, err := parseHistoryPage(&apiResponse{status: 200, body: []byte(`{"data":[
		{"request_id":"00000000-0000-4000-8000-000000000001","user_hid":"9f86d081884c7d659a2feaa0c55ad015"},
		{"request_id":"00000000-0000-4000-8000-000000000002","user_hid":"9f86d081884c7d659a2feaa0c55ad015"},
		{"request_id":"00000000-0000-4000-8000-000000000003","user_hid":"60303ae22b998861bce3b28f33eec1be"},
		{"request_id":"00000000-0000-4000-8000-000000000004","user_hid":"anonymous"},
		{"request_id":"00000000-0000-4000-8000-000000000005","user_hid":"fail"},
		{"request_id":"00000000-0000-4000-8000-000000000006","user_hid":"-1"},
		{"request_id":"00000000-0000-4000-8000-000000000007","user_hid":"unknown"},
		{"request_id":"00000000-0000-4000-8000-000000000008","user_hid":""}
	],"total":8}`)})
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]bool{}
	for _, ident := range page.Data {
		if hid, ok := ident.AccountUserHID(); ok {
			accounts[hid] = true
		}
	}
	if len(accounts) != 2 {
		t.Errorf("accounts = %v, want the 2 real User HIDs", accounts)
	}
}
