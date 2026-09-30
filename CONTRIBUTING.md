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
