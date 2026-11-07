# Contributing to AgentBox

Thanks for your interest! AgentBox is in the pre-MVP stage; see [docs/MVP_Task_List.md](docs/MVP_Task_List.md) for current work and [docs/threat-model.md](docs/threat-model.md) for security scope.

## Development

Requirements: Go 1.24+, Docker (Linux engine), Node 22+ (for the UI, later phases).

```bash
make build   # build all binaries into ./bin
make test    # go test -race ./...
make vet
make lint    # requires golangci-lint
```

## Guidelines

- Keep the single Go module layout: `cmd/` (binaries), `internal/` (libraries), `web/` (UI), `deploy/`, `test/`.
- Security-relevant changes (network rules, mounts, privileges, policy decisions) need a matching negative test and a note in the PR describing the trust boundary affected.
- Fail closed: if enforcement is unavailable, deny.
- Never log secrets, prompts, or file contents by default.
- Architecture decisions go in `docs/adr/` as a new numbered ADR.
- Never expose `docker.sock` to agents, MCP servers, or the controller.

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0.
