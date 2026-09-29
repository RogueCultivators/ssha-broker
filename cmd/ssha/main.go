// Command ssha is an SSH broker for AI agents: it holds the host inventory and
// credentials, enforces per-host policy, records a tamper-evident audit log,
// and exposes the result as both a CLI and a Model Context Protocol server.
package main

import (
	"os"

	"ssha/internal/cli"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "0.1.0-dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], version))
}
