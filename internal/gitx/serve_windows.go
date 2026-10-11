//go:build windows

package gitx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func replaceProcess(bin string, args []string) int {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
	return 1
}
