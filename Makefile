BINARY  := ssha
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX  ?= $(HOME)/.local
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build desktop test vet fmt e2e clean install install-system \
        package-deb package-appimage package-macos package-windows

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ssha

# The binary is self-contained, so installing is a copy.
install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "installed $(PREFIX)/bin/$(BINARY) ($(VERSION))"

# The desktop build adds the native window. The plain build above stays pure Go
# so that the CLI and the MCP server keep compiling anywhere.
desktop:
	./scripts/build-desktop.sh $(BINARY)

VERSION_NUM := $(shell git describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0)

package-deb: desktop
	mkdir -p dist && cp $(BINARY) dist/ssha
	ARCH=$${ARCH:-amd64} VERSION=$(VERSION_NUM) \
		nfpm package -f packaging/nfpm.yaml -p deb -t dist/

package-appimage: desktop
	mkdir -p dist && cp $(BINARY) dist/ssha
	./packaging/appimage/build.sh dist/ssha $(VERSION_NUM) dist/ssha-$(VERSION_NUM)-$$(uname -m).AppImage

package-macos: desktop
	./packaging/macos/bundle.sh $(BINARY) $(VERSION_NUM) dist/$(BINARY).app

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
