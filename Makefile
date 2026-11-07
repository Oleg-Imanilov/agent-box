BINS := agentbox controller netgw mcpgw
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/Oleg-Imanilov/agent-box/internal/version.Version=$(VERSION)

.PHONY: build test vet lint vuln spike-net clean

build:
	@mkdir -p bin
	@for b in $(BINS); do go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; done

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

vuln:
	govulncheck ./...

# Docker network isolation spike (requires Docker); see docs/spikes/network-isolation.md
spike-net:
	sh test/spikes/network/run.sh

clean:
	rm -rf bin dist
