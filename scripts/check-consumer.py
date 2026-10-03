#!/usr/bin/env python3
"""Install a fresh module archive through a local Go proxy, then use the SDK."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/ShieldLabs-ai/shieldlabs-go"
ESCAPED = "github.com/!shield!labs-ai/shieldlabs-go"
VERSION = "v1.0.0"

CONSUMER = '''package main
import (
 "context"
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "net/http"
 "net/http/httptest"
 shield "github.com/ShieldLabs-ai/shieldlabs-go"
 "github.com/ShieldLabs-ai/shieldlabs-go/webhook"
)
func main() {
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path == "/v1/profile" {
   if r.Header.Get("X-Shield-Domain") != "example.com" { panic("domain header") }
   fmt.Fprint(w, `{"Domain":"example.com","Weight":-3,"future":true}`)
  } else {
   if r.URL.Query().Get("limit") != "1" { panic("query") }
   fmt.Fprint(w, `{"data":[{"request_id":"fixture","score":999,"connection_type":"future"}],"total":1}`)
  }
 }))
 defer srv.Close()
 client, err := shield.NewClient("sec_fixture", shield.WithBaseURL(srv.URL)); if err != nil { panic(err) }
 page, err := client.History.Search(context.Background(), shield.LookupUserHID, "anonymous", &shield.HistorySearchOptions{Limit:1})
 if err != nil || page.Total != 1 || page.Data[0].RiskScore != 999 || string(page.Data[0].ConnectionType) != "future" { panic("history") }
 management, err := shield.NewManagementClient("fixture", "example.com", shield.WithBaseURL(srv.URL)); if err != nil { panic(err) }
 profile, err := management.GetProfile(context.Background()); if err != nil || profile.RemainingIdentifications != -3 || profile.Raw["future"] != true { panic("profile") }
 payload := []byte(`{"event_type":"identification.scored","data":{"risk_score":999,"signals":[{"name":"future","weight":-30},{"name":"future","weight":-30}],"detection_flags":{"vpn":true}}}`)
 mac := hmac.New(sha256.New, []byte("whsec_fixture")); mac.Write(payload)
 event, err := webhook.ConstructEvent(payload, "sha256="+hex.EncodeToString(mac.Sum(nil)), "whsec_fixture"); if err != nil { panic(err) }
 data := event.(*webhook.IdentificationScoredEvent).Data
 if data.RiskScore != 999 || len(data.Signals) != 2 || data.Signals[0].Weight != -30 || !data.DetectionFlags.VPN { panic("webhook") }
 fmt.Println("PASS installed archive: History, profile and signed webhook")
}
'''

with tempfile.TemporaryDirectory(prefix=".consumer-check-", dir=ROOT) as directory:
    scratch = Path(directory)
    proxy = scratch / "proxy" / ESCAPED / "@v"
    proxy.mkdir(parents=True)
    (proxy / f"{VERSION}.mod").write_bytes((ROOT / "go.mod").read_bytes())
    (proxy / f"{VERSION}.info").write_text(json.dumps({"Version": VERSION, "Time": "2026-09-30T00:00:00Z"}))
    with zipfile.ZipFile(proxy / f"{VERSION}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        # The supported module has only standard-library dependencies. Include
        # its real source tree; the separate generated reference module is not a dependency.
        files = [ROOT / "go.mod"] + sorted(ROOT.glob("*.go")) + sorted((ROOT / "internal").rglob("*.go")) + sorted((ROOT / "webhook").rglob("*.go"))
        for path in files:
            if not path.name.endswith("_test.go"):
                archive.write(path, f"{MODULE}@{VERSION}/{path.relative_to(ROOT).as_posix()}")
    consumer = scratch / "consumer"
    consumer.mkdir()
    (consumer / "go.mod").write_text(f"module consumer\n\ngo 1.23\n\nrequire {MODULE} {VERSION}\n")
    (consumer / "main.go").write_text(CONSUMER)
    local = bool(shutil.which("go"))
    base = scratch if local else Path("/check")
    env = {"GOPROXY": f"file://{base}/proxy", "GOSUMDB": "off", "GOMODCACHE": str(base / "modcache"), "GOMAXPROCS": "2"}
    command = ["go"] if local else ["docker", "run", "--rm", "-v", f"{scratch}:/check", "-v", "shieldlabs-sdk-gocache:/root/.cache/go-build", "-w", "/check/consumer"] + [arg for k, v in env.items() for arg in ("-e", f"{k}={v}")] + ["golang:1.24-bookworm", "go"]
    subprocess.run(command + ["run", "-mod=mod", "."], cwd=consumer, env={**os.environ, **env}, check=True, timeout=180)
