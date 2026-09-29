BINARY  := ssha
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt e2e smoke clean install

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ssha

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/ssha

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Full end-to-end run against a throwaway sshd container (needs docker).
e2e:
	./scripts/e2e.sh

clean:
	rm -f $(BINARY)
	rm -rf dist
