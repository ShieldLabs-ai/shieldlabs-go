#!/usr/bin/env python3
"""Compile the supported SDK against regenerated, incompatible schemas."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("generator", ROOT / "scripts/generate-contract.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
document = yaml.safe_load((ROOT / "resources/shieldlabs-api.yaml").read_text())


method_failures = []
for operation_id in ("searchHistory", "getDomainProfile"):
    schema = copy.deepcopy(document)
    for item in schema["paths"].values():
        if item.get("get", {}).get("operationId") == operation_id:
            item["post"] = item.pop("get")
            break
    else:
        raise AssertionError(f"Missing GET operation {operation_id}")
    try:
        changed = generator.generate(schema)
    except ValueError as error:
        assert f"Unsupported HTTP method for {operation_id}: POST; expected GET" in str(error), str(error)
        print(f"PASS generator rejects GET-to-POST change for {operation_id}", flush=True)
    else:
        same = changed == generator.generate(document)
        method_failures.append(operation_id)
        print(f"FAIL GET-to-POST change accepted for {operation_id}; byte_identical={same}", flush=True)
if method_failures:
    raise AssertionError("HTTP method changes must stop generation: " + ", ".join(method_failures))


def compile_schema(schema, expected=None, coverage=False):
    generated = generator.generate(schema)
    with tempfile.TemporaryDirectory(prefix=".contract-check-", dir=ROOT) as directory:
        scratch = Path(directory)
        target = scratch / "models.gen.go"
        target.write_bytes(generated)
        local = bool(shutil.which("go"))
        base = ROOT if local else Path("/src")
        overlay = scratch / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(base / "internal/contract/models.gen.go"): str(base / scratch.name / target.name)}}))
        go = ["go"] if local else ["docker", "run", "--rm", "-e", "GOMAXPROCS=2", "-v", f"{ROOT}:/src", "-v", "shieldlabs-sdk-gocache:/root/.cache/go-build", "-w", "/src", "golang:1.24-bookworm", "go"]
        command = go + (["test", "-run", "^TestGenerated(ContractCoverage|RequestBuilders)$", "-count=1"] if coverage else ["build"])
        command += ["-p=2", f"-overlay={base / scratch.name / overlay.name}", "./..."]
        result = subprocess.run(command, cwd=ROOT, env={**os.environ, "GOMAXPROCS": "2"}, capture_output=True, text=True, timeout=180)
        output = result.stdout + result.stderr
        if expected:
            assert result.returncode != 0 and expected in output, f"Expected SDK failure in {expected}:\n{output}"
            print(f"PASS incompatible schema rejected by {expected}", flush=True)
        else:
            assert result.returncode == 0, output
            print("PASS compatible schema compiles", flush=True)


assert generator.generate(document) == generator.OUTPUT.read_bytes(), "Generate the wire views first"
compile_schema(document, coverage=True)


def changed(section, component, update, expected, coverage=False):
    schema = copy.deepcopy(document)
    update(schema["components"][section][component])
    compile_schema(schema, expected, coverage)


def rename_property(old, new):
    def update(schema):
        schema["properties"][new] = schema["properties"].pop(old)
        schema["required"] = [new if name == old else name for name in schema.get("required", [])]
    return update


def type_property(name, kind):
    return lambda schema: schema["properties"].__setitem__(name, {"type": kind})


changed("schemas", "HistoryRow", rename_property("score", "risk_points"), "normalize.go")
changed("schemas", "HistoryRow", type_property("score", "string"), "normalize.go")
changed("schemas", "HistoryPage", type_property("total", "string"), "history.go")
changed("schemas", "DomainProfile", type_property("Weight", "string"), "management.go")
changed("parameters", "ShieldDomain", lambda s: s.update(name="X-Site-Domain"), "management.go")
changed("parameters", "HistoryLimit", lambda s: s["schema"].update(type="string"), "history.go")
changed("parameters", "HistoryLimit", lambda s: s.update(name="page_size"), "history.go")
changed("parameters", "HistorySearchType", lambda s: s.update(name="lookup_type"), "history.go")
changed("schemas", "IdentificationScoredData", type_property("risk_score", "string"), "normalize.go")
changed("schemas", "DetectionFlags", type_property("vpn", "integer"), "contract.go")
changed("schemas", "IdentificationScoredEvent", rename_property("data", "result"), "webhook/webhook.go")
changed("schemas", "Signal", type_property("weight", "string"), "normalize.go")
changed("schemas", "ScoreDetail", type_property("Value", "string"), "normalize.go")
for field in ("event_type", "created_at", "schema_version"):
    changed("schemas", "WebhookPingEvent", rename_property(field, f"renamed_{field}"), "webhook/webhook.go")
    changed("schemas", "WebhookPingEvent", type_property(field, "integer"), "webhook/webhook.go")
changed("schemas", "DetectionFlags", lambda s: s["properties"].update(extra_flag={"type": "boolean"}), "generated flag coverage", coverage=True)
changed("parameters", "HistorySearchType", lambda s: s["schema"]["enum"].append("account_id"), "generated lookup coverage", coverage=True)

schema = copy.deepcopy(document)
schema["components"]["schemas"]["HistoryRow"]["properties"]["future_diagnostic"] = {"type": "string"}
compile_schema(schema)
print("PASS optional additive field remains compatible")


def add_parameter(op_id, location, required, referenced=False, path_level=False):
    schema = copy.deepcopy(document)
    name = "X-Future-Option" if location == "header" else "future_option"
    parameter = {"name": name, "in": location, "required": required, "schema": {"type": "string", "default": "server-default"}}
    for item in schema["paths"].values():
        operation = item.get("get", {})
        if operation.get("operationId") == op_id:
            if referenced:
                schema["components"]["parameters"]["FutureOption"] = parameter
                parameter = {"$ref": "#/components/parameters/FutureOption"}
            owner = item if path_level else operation
            owner.setdefault("parameters", []).append(parameter)
            return schema
    raise AssertionError(f"Missing operation {op_id}")


for component, operation, location in (
    ("HistoryLimit", "searchHistory", "header"),
    ("HistoryOffset", "searchHistory", "header"),
    ("HistorySearchType", "searchHistory", "query"),
    ("HistoryValue", "searchHistory", "query"),
    ("ShieldDomain", "getDomainProfile", "query"),
):
    schema = copy.deepcopy(document)
    schema["components"]["parameters"][component]["in"] = location
    try:
        generator.generate(schema)
    except ValueError as error:
        assert f"Parameter location changed in {operation}:" in str(error), str(error)
    else:
        raise AssertionError(f"Moved parameter {component} escaped generation")
    print(f"PASS generator rejects moved parameter {component}", flush=True)


for operation in ("searchHistory", "getDomainProfile"):
    for location in ("path", "query", "header"):
        for referenced in (False, True):
            schema = add_parameter(operation, location, True, referenced, path_level=referenced)
            try:
                generator.generate(schema)
            except ValueError as error:
                assert f"Unsupported required parameter in {operation}: {location}" in str(error), str(error)
            else:
                raise AssertionError(f"New required {location} in {operation} escaped generation")
            print(f"PASS generator rejects new required {location} in {operation} (referenced={referenced})", flush=True)
    for location in ("query", "header"):
        schema = add_parameter(operation, location, False, referenced=True, path_level=True)
        compile_schema(schema, coverage=True)
        print(f"PASS optional {location} in {operation} is not sent, including its default", flush=True)
