BINARY  := ssha
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX  ?= $(HOME)/.local
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt e2e clean install install-system

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ssha

# The binary is self-contained, so installing is a copy.
install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "installed $(PREFIX)/bin/$(BINARY) ($(VERSION))"

# Needs root: a system-wide copy plus the dedicated-user service.
install-system:
	sudo ./packaging/install.sh --system

install-user:
	./packaging/install.sh --user

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
