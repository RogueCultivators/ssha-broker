//go:build !windows

package main

// reportFatal is a no-op off Windows: the same message already reached stderr,
// which a window build on Linux and macOS still has.
func reportFatal(string) {}
