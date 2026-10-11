//go:build unix

package gitx

import (
	"fmt"
	"os"
	"syscall"
)

// replaceProcess is what git's SSH command must do: become ssh, so a signal
// from git reaches ssh and not a leftover wrapper.
func replaceProcess(bin string, args []string) int {
	argv := append([]string{bin}, args...)
	err := syscall.Exec(bin, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "ssha: exec ssh: %v\n", err)
	return 1
}
