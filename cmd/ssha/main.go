// Command ssha is an SSH broker for AI agents: it holds the host inventory and
// credentials, enforces per-host policy, records a tamper-evident audit log,
// and exposes the result as both a CLI and a Model Context Protocol server.
package main

import (
	"bytes"
	"io"
	"os"
	"strings"

	"ssha/internal/cli"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "0.1.0-dev"

// windowBuild is "1" in the window-subsystem binary (Windows, -H=windowsgui).
// That process has no console: an error printed to stderr goes nowhere and the
// window never appears with no hint why. It defaults to the editor and shows a
// dialog when it fails.
var windowBuild = ""

// defaultCommand is what to run when no arguments are given. The window build
// sets it to "ui" so that double-clicking the exe opens the window instead of
// printing usage into a console that does not exist.
var defaultCommand = ""

func main() {
	args := os.Args[1:]
	if defaultCommand != "" && len(args) == 0 {
		args = []string{defaultCommand}
	}
	if windowBuild == "" {
		os.Exit(cli.Run(args, version))
	}
	// Capture first: io.MultiWriter stops at the first writer that fails, and
	// stderr is an invalid handle in a GUI process.
	var errBuf bytes.Buffer
	code := cli.RunStreams(args, version, os.Stdout, io.MultiWriter(&errBuf, os.Stderr))
	if code != 0 && errBuf.Len() > 0 {
		reportFatal(strings.TrimSpace(errBuf.String()))
	}
	os.Exit(code)
}
