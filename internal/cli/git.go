package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"ssha/internal/audit"
	"ssha/internal/gitx"
)

const gitUsage = `ssha git accounts
ssha git which [-C DIR] [--remote NAME] [URL]
ssha git fetch|pull|push|ls-remote [-C DIR] [--remote NAME] [--] [git args]
ssha git clone [-C DIR] [--] <URL> [directory]

The account is chosen from the remote host. A password or key stays on this
machine; it is not put in the URL, the arguments, or the output.

Flags that belong to ssha come first. Everything after them is passed to git.
--force is refused unless that account sets allow_force.
`

func (a *App) cmdGit(args []string) int {
	if a.groupHelp("git", gitUsage, args) || len(args) == 0 {
		if len(args) == 0 {
			return a.usageErr("usage: ssha git <accounts|which|fetch|pull|push|clone|ls-remote>")
		}
		return ExitOK
	}
	switch args[0] {
	case "accounts", "list":
		return a.cmdGitAccounts(args[1:])
	case "which":
		return a.cmdGitWhich(args[1:])
	case "fetch", "pull", "push", "clone", "ls-remote":
		return a.cmdGitRun(args[0], args[1:])
	default:
		return a.usageErr(fmt.Sprintf("unknown git subcommand %q", args[0]))
	}
}

func (a *App) cmdGitAccounts(args []string) int {
	flags, err := a.splitGitArgs(args)
	if err != nil {
		return a.usageErr(err.Error())
	}
	if len(flags.rest) > 0 || flags.url != "" || flags.dir != "" {
		return a.usageErr("ssha git accounts takes no arguments")
	}
	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()
	accounts := b.GitAccounts()
	a.emit(map[string]any{"accounts": accounts, "count": len(accounts)}, func() string {
		if len(accounts) == 0 {
			return "no git accounts\n"
		}
		var sb strings.Builder
		for _, ac := range accounts {
			ready := "no credential"
			switch {
			case ac.Auth == "https" && ac.PasswordReady:
				ready = "password saved"
			case ac.Auth == "https":
				ready = "password missing"
			case ac.KeyConfigured:
				ready = "key configured"
			}
			fmt.Fprintf(&sb, "%s  %s  %s  %s", ac.Name, ac.Auth, strings.Join(ac.Hosts, ","), ready)
			if ac.PathPrefix != "" {
				fmt.Fprintf(&sb, "  prefix=%s", ac.PathPrefix)
			}
			if ac.Disabled {
				sb.WriteString("  disabled")
			}
			sb.WriteByte('\n')
		}
		return sb.String()
	})
	return ExitOK
}

func (a *App) cmdGitWhich(args []string) int {
	flags, err := a.splitGitArgs(args)
	if err != nil {
		return a.usageErr(err.Error())
	}
	url := flags.url
	if url == "" && len(flags.rest) == 1 {
		url = flags.rest[0]
	} else if len(flags.rest) > 1 || (url != "" && len(flags.rest) > 0) {
		return a.usageErr("usage: ssha git which [-C DIR] [--remote NAME] [URL]")
	}
	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()
	if url == "" {
		url, err = gitRemoteURL(flags.dir, flags.remote)
		if err != nil {
			return a.fail(err)
		}
	}
	remote, err := gitx.ParseRemote(url)
	if err != nil {
		return a.fail(err)
	}
	account, err := b.Config().MatchGit(remote.Host, remote.EffectivePort(), remote.Path)
	if err != nil {
		return a.fail(err)
	}
	pub := account.Public()
	a.emit(map[string]any{
		"url":     remote.Sanitized(),
		"host":    remote.Host,
		"path":    remote.Path,
		"account": pub,
	}, func() string {
		return fmt.Sprintf("%s  ->  %s (%s)\n", remote.Sanitized(), pub.Name, pub.Auth)
	})
	return ExitOK
}

func (a *App) cmdGitRun(op string, args []string) int {
	flags, err := a.splitGitArgs(args)
	if err != nil {
		return a.usageErr(err.Error())
	}
	if flags.dir == "" {
		flags.dir = "."
	}
	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := b.Git(ctx, gitx.Request{
		Op:     op,
		Dir:    flags.dir,
		Remote: flags.remote,
		URL:    flags.url,
		Args:   flags.rest,
	})
	if res == nil {
		return a.fail(err)
	}
	a.emit(res, func() string { return renderGitText(res) })
	if res.Decision == audit.DecisionDenied {
		return ExitDenied
	}
	if err != nil {
		return ExitFail
	}
	if res.ExitCode != 0 {
		return normalizeExit(res.ExitCode)
	}
	return ExitOK
}

func renderGitText(res *gitx.Result) string {
	if res.Decision == audit.DecisionDenied {
		var sb strings.Builder
		fmt.Fprintf(&sb, "DENIED: %s\n", res.Reason)
		if res.AuditID != "" {
			fmt.Fprintf(&sb, "audit: %s\n", res.AuditID)
		}
		return sb.String()
	}
	var sb strings.Builder
	sb.WriteString(res.Stdout)
	if res.Stderr != "" {
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), "\n") {
			sb.WriteByte('\n')
		}
		sb.WriteString(res.Stderr)
		if !strings.HasSuffix(res.Stderr, "\n") {
			sb.WriteByte('\n')
		}
	}
	if res.Truncated {
		fmt.Fprintf(&sb, "ssha: output truncated; full output in audit log %s\n", res.AuditID)
	}
	return sb.String()
}

type gitFlags struct {
	dir, remote, url string
	rest             []string
}

func (a *App) splitGitArgs(args []string) (gitFlags, error) {
	out := gitFlags{remote: "origin"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out.rest = append(out.rest, args[i+1:]...)
			return out, nil
		}
		take := func() (string, error) {
			i++
			if i >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			return args[i], nil
		}
		switch {
		case arg == "-C" || arg == "--dir":
			v, err := take()
			if err != nil {
				return out, err
			}
			out.dir = v
		case strings.HasPrefix(arg, "--dir="):
			out.dir = strings.TrimPrefix(arg, "--dir=")
		case arg == "--remote":
			v, err := take()
			if err != nil {
				return out, err
			}
			out.remote = v
		case strings.HasPrefix(arg, "--remote="):
			out.remote = strings.TrimPrefix(arg, "--remote=")
		case arg == "--url":
			v, err := take()
			if err != nil {
				return out, err
			}
			out.url = v
		case strings.HasPrefix(arg, "--url="):
			out.url = strings.TrimPrefix(arg, "--url=")
		case arg == "--json":
			a.JSON = true
		case arg == "--no-prompt":
			a.NoPrompt = true
		case arg == "--reveal":
			a.Reveal = true
		case arg == "-c" || arg == "--config":
			v, err := take()
			if err != nil {
				return out, err
			}
			a.ConfigPath = v
		case strings.HasPrefix(arg, "--config="):
			a.ConfigPath = strings.TrimPrefix(arg, "--config=")
		default:
			out.rest = append(out.rest, args[i:]...)
			return out, nil
		}
	}
	return out, nil
}

func gitRemoteURL(dir, name string) (string, error) {
	if dir == "" {
		dir = "."
	}
	cmd := exec.Command("git", "-C", dir, "remote", "get-url", name)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git remote get-url %s: %w", name, err)
	}
	url := strings.TrimSpace(string(out))
	if url == "" {
		return "", fmt.Errorf("git remote %s has no URL", name)
	}
	return url, nil
}
