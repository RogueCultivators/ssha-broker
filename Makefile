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

# Package names cannot carry a commit hash, so this is not the same as VERSION.
VERSION_NUM := $(shell ./scripts/version.sh)

package-deb: desktop
	mkdir -p dist && cp $(BINARY) dist/ssha
	ARCH=$${ARCH:-amd64} VERSION=$(VERSION_NUM) \
		nfpm package -f packaging/nfpm.yaml -p deb -t dist/

package-appimage: desktop
	mkdir -p dist && cp $(BINARY) dist/ssha
	./packaging/appimage/build.sh dist/ssha $(VERSION_NUM) dist/ssha-$(VERSION_NUM)-$$(uname -m).AppImage

package-macos: desktop
	./packaging/macos/bundle.sh $(BINARY) $(VERSION_NUM) dist/$(BINARY).app

# Cross compiles the Windows build. WebView2.h includes "EventToken.h" with a
# capital E, which is fine on Windows and not fine on a case-sensitive
# filesystem, so a one-line shim goes on the include path.
#
# Two binaries come out of it: ssha.exe (console: CLI and MCP) and ssha-ui.exe
# (window subsystem: the editor, with no console window). The installer, the
# Start Menu shortcut and the autostart entry all use the window one.
WIN_CGO := CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
	CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
	CGO_CFLAGS=-I$(CURDIR)/.win-shim CGO_CXXFLAGS=-I$(CURDIR)/.win-shim

package-windows:
	mkdir -p dist .win-shim
	printf '#include <eventtoken.h>\n' > .win-shim/EventToken.h
	go run packaging/windows/genrc.go -version $(VERSION_NUM) \
		-icon packaging/icons/ssha.ico -out packaging/windows/ssha.rc
	x86_64-w64-mingw32-windres -i packaging/windows/ssha.rc \
		-o cmd/ssha/rsrc_windows_amd64.syso
	$(WIN_CGO) go build -tags desktop -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/ssha.exe ./cmd/ssha
	$(WIN_CGO) go build -tags desktop -trimpath \
		-ldflags "$(LDFLAGS) -H=windowsgui -X main.windowBuild=1 -X main.defaultCommand=ui" \
		-o dist/ssha-ui.exe ./cmd/ssha
	cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 \
		packaging/windows/README-Windows.txt dist/
	cd dist && zip -q ssha-$(VERSION_NUM)-windows-x64.zip \
		ssha.exe ssha-ui.exe install.ps1 uninstall.ps1 README-Windows.txt
	@echo "dist/ssha-$(VERSION_NUM)-windows-x64.zip"

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
	rm -rf dist .win-shim
	rm -f packaging/windows/ssha.rc cmd/ssha/rsrc_windows_amd64.syso
