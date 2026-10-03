# Contributing

Thanks for helping improve the ShieldLabs Go SDK. Bug reports and pull requests are welcome.
For questions about your ShieldLabs account, write to [contact@shieldlabs.ai](mailto:contact@shieldlabs.ai).

## Setup

You need Go 1.23 or later, or Docker. The module has no third-party dependencies.

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race -cover ./...
go build ./...
```

The same checks in Docker:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm \
  sh -c 'test -z "$(gofmt -l .)" && go vet ./... && go test -race -cover ./... && go build ./...'
```

## Generated contract

The API resource in `resources/shieldlabs-api.yaml` generates the typed views in
`internal/contract/models.gen.go`. The supported client reads them before applying its
existing tolerant conversions. Keep normalization and transport handwritten; never
replace permissive decoding with a strict generated JSON decoder.

With Python 3.9+ and either Go or Docker:

```sh
python3 -m pip install -r scripts/requirements.txt
python3 scripts/generate-contract.py
python3 scripts/generate-contract.py --check
python3 scripts/check-contract-drift.py
python3 scripts/check-consumer.py
```

The drift check regenerates incompatible schemas in temporary overlays and requires
the supported client to reject them through compilation or contract coverage tests.
An optional additive field must still compile. The consumer check installs a fresh
module ZIP through an isolated local file proxy, then exercises History, profile and
signed webhook calls with synthetic responses. Neither check calls the live API.

The generator's consumed-parameter mapping records the inputs supplied by public
SDK methods. New required request parameters stop generation until those callers
are updated. New optional parameters are omitted, not sent as empty values or
copied defaults. A consumed parameter changing its path/query/header location also
stops generation until its transport caller is updated. Ping envelopes use their own generated model; drift checks cover
renames and type changes of its event type, timestamp and schema version.
History and profile operations also stop generation if their HTTP method changes
from GET, requiring the supported transport caller to be updated explicitly.

`./generate.sh` also rebuilds the separate reference client under `generated/`.
Do not edit generated files by hand. Change the resource or generator and rerun it.

CI also runs staticcheck with Go 1.24:

```sh
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
```

## Guidelines

- Keep the public API small and idiomatic: `context.Context` first, functional options,
  errors that work with `errors.Is` and `errors.As`, no global state.
- Standard library only.
- Every change needs tests. Keep line coverage above 90 %.
- `testdata/` holds shared test fixtures that every ShieldLabs server SDK passes. Keep them
  byte-exact: do not edit or reformat them by hand. Tests must keep passing all of them.
- Documentation and comments use plain, technical English. Follow the existing wording for
  product terms (identification, request ID, risk signals, risk bands).
- Commit messages follow the conventional style: `feat: ...`, `fix: ...`, `docs: ...`,
  `test: ...`, `ci: ...`.

## Releasing

Update `Version` in `shieldlabs.go` and add the version's section to `CHANGELOG.md`, then
push a semantic version tag:

```sh
git tag v1.0.0
git push origin v1.0.0
```

The release workflow tests the tagged commit, checks that `Version` matches the tag, creates
the GitHub release from the changelog section (or updates it when the workflow is re-run) and
asks the Go module proxy to index the version so that it appears on pkg.go.dev. A tag with a
pre-release suffix such as `v1.1.0-rc.1` creates a pre-release.

The Go module proxy keeps every tagged version permanently, so protect `v*` tags with a tag
ruleset that only maintainers can bypass, and never move a published tag.
