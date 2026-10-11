package gitx

import (
	"fmt"
	"os"
	"os/exec"
)

// ServeCredential is the git-credential helper. It writes the password only to
// stdout, which git reads, and never to stderr.
func ServeCredential(args []string) int {
	action := "get"
	if len(args) > 0 {
		action = args[0]
	}
	g, err := LoadGrant()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	out, err := Credential(action, os.Stdin, g)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	fmt.Fprint(os.Stdout, out)
	return 0
}

// ServeAskpass answers an ssh passphrase prompt. A host-key confirmation is
// refused so an unknown server is not accepted by accident.
func ServeAskpass(args []string) int {
	prompt := ""
	if len(args) > 0 {
		prompt = args[0]
	}
	g, err := LoadGrant()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	answer, err := AskPassAnswer(prompt, g)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, answer)
	return 0
}

// ServeSSH replaces this process's job with the real ssh, using only the key
// in the grant. git invokes it as the SSH command.
func ServeSSH(args []string) int {
	g, err := LoadGrant()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	sshArgs, err := SSHArgs(g, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	bin, err := findSSH()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssha: %v\n", err)
		return 1
	}
	return replaceProcess(bin, sshArgs)
}

func findSSH() (string, error) {
	for _, p := range []string{"/usr/bin/ssh", "/usr/local/bin/ssh"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	p, err := exec.LookPath("ssh")
	if err != nil {
		return "", fmt.Errorf("ssh is not installed or not on PATH")
	}
	return p, nil
}
