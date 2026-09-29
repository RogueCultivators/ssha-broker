// Package cli implements the ssha command line interface.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ssha/internal/broker"
)

// Exit codes. They are stable so agents and scripts can branch on them.
const (
	ExitOK     = 0
	ExitFail   = 1
	ExitUsage  = 2
	ExitDenied = 77 // EX_NOPERM
)

const usage = `ssha - an SSH broker for AI agents, with policy and auditing

Usage:
  ssha <command> [flags] [args]

Commands:
  init                     write a starter config file
  hosts [list]             list configured hosts
  hosts find <words...>    find a host by its note, e.g. hosts find payment
  hosts show <name>        show one host's details, including its note
  hosts test <name>...     verify host key, credentials and command execution
  hosts import [file]      read hosts from an ssh_config file
  host-key <host|addr>     fetch a host's public keys (onboarding aid)
  run <host> [--] <cmd>    run a command on one host
  multi [--tag T] <cmd>    run a command on several hosts in parallel
  multi -q <words> <cmd>   ...on every host matching a search
  upload <host> <src> <dst>   upload a file (src "-" reads stdin)
  download <host> <src> <dst> download a file (dst "-" writes stdout)
  policy check <host> <cmd>   evaluate policy without executing
  audit ls                 list recent audit records
  audit show <id>          show one audit record
  audit verify             verify the audit hash chain
  mcp                      serve MCP on stdio (for coding agents)
  ui                       open the config editor in a desktop window
  ui --headless            ...or as a local http service, printing the url
  skill install            install the agent skill into ~/.agents/skills
  skill print              print the agent skill to stdout
  version                  print the version

Global flags (before the command):
  -c, --config PATH   config file (default: $SSHA_CONFIG, ./ssha.yaml, ~/.config/ssha/config.yaml)
      --json          machine-readable output
      --reveal        operator mode: show real host details, do not redact output
      --no-prompt     never ask for a password or passphrase interactively
  -h, --help          show help

Exit codes:
  0 success   1 failure   2 usage error   77 command denied by policy
`

// App carries process-wide state.
type App struct {
	ConfigPath string
	JSON       bool
	NoPrompt   bool
	Reveal     bool
	Version    string
	Stdout     io.Writer
	Stderr     io.Writer

	// cmd is the subcommand being run, so that `ssha <cmd> --help` can name it.
	cmd string
	// shared holds the flags every command carries, which are listed once in the
	// general usage rather than repeated under each command.
	shared map[string]bool
}

// Run is the CLI entry point. It returns the process exit code.
func Run(args []string, version string) int {
	a := &App{Version: version, Stdout: os.Stdout, Stderr: os.Stderr}

	global := flag.NewFlagSet("ssha", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	global.StringVar(&a.ConfigPath, "config", "", "")
	global.StringVar(&a.ConfigPath, "c", "", "")
	global.BoolVar(&a.JSON, "json", false, "")
	global.BoolVar(&a.NoPrompt, "no-prompt", false, "")
	global.BoolVar(&a.Reveal, "reveal", false, "")
	help := global.Bool("help", false, "")
	global.BoolVar(help, "h", false, "")

	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.Stdout, usage)
			return ExitOK
		}
		return a.usageErr(err.Error())
	}
	if *help {
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	}

	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(a.Stdout, usage)
		return ExitUsage
	}

	cmd, sub := rest[0], rest[1:]
	a.cmd = cmd
	switch cmd {
	case "init":
		return a.cmdInit(sub)
	case "hosts":
		return a.cmdHosts(sub)
	case "host-key", "hostkey":
		return a.cmdHostKey(sub)
	case "run":
		return a.cmdRun(sub)
	case "multi":
		return a.cmdMulti(sub)
	case "upload":
		return a.cmdUpload(sub)
	case "download":
		return a.cmdDownload(sub)
	case "policy":
		return a.cmdPolicy(sub)
	case "audit":
		return a.cmdAudit(sub)
	case "mcp":
		return a.cmdMCP(sub)
	case "ui":
		return a.cmdUI(sub)
	case "skill":
		return a.cmdSkill(sub)
	case "version", "--version", "-v":
		fmt.Fprintf(a.Stdout, "ssha %s\n", a.Version)
		return ExitOK
	case "help":
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	default:
		return a.usageErr(fmt.Sprintf("unknown command %q", cmd))
	}
}

func (a *App) usageErr(msg string) int {
	fmt.Fprintf(a.Stderr, "ssha: %s\n\n", msg)
	fmt.Fprint(a.Stderr, usage)
	return ExitUsage
}

func (a *App) fail(err error) int {
	fmt.Fprintf(a.Stderr, "ssha: %v\n", err)
	return ExitFail
}

// open loads the broker, honouring --config, --reveal and prompting.
func (a *App) open() (*broker.Broker, error) {
	b, err := broker.OpenDefaultWithOptions(a.ConfigPath, broker.Options{
		Prompt: a.promptFunc(),
		Reveal: a.Reveal,
	})
	if err != nil {
		if errors.Is(err, broker.ErrNoConfig) {
			return nil, fmt.Errorf("%w\n\nCreate one with `ssha init` or pass --config PATH", err)
		}
		return nil, err
	}
	return b, nil
}

// emit writes either JSON or the fallback text rendering.
func (a *App) emit(v any, text func() string) {
	if a.JSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			fmt.Fprintf(a.Stderr, "ssha: encode json: %v\n", err)
		}
		return
	}
	if text != nil {
		fmt.Fprint(a.Stdout, text())
	}
}

// newFlagSet builds a subcommand flag set that shares the global flags.
func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&a.ConfigPath, "config", a.ConfigPath, "path to the config file")
	fs.StringVar(&a.ConfigPath, "c", a.ConfigPath, "shorthand for -config")
	fs.BoolVar(&a.JSON, "json", a.JSON, "machine readable output, where supported")
	fs.BoolVar(&a.NoPrompt, "no-prompt", a.NoPrompt, "never ask for a password")
	fs.BoolVar(&a.Reveal, "reveal", a.Reveal, "show real addresses and users instead of placeholders")
	a.shared = make(map[string]bool, 5)
	for _, name := range []string{"config", "c", "json", "no-prompt", "reveal"} {
		a.shared[name] = true
	}
	return fs
}

// parse runs a flag set and reports usage errors consistently.
func (a *App) parse(fs *flag.FlagSet, args []string) (int, bool) {
	return a.parseErr(fs, fs.Parse(args))
}

// parseErr turns a flag error into an exit code. Asking for help is not a
// mistake, and the general usage text does not list a command's own flags:
// `--headless` is only discoverable here.
func (a *App) parseErr(fs *flag.FlagSet, err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	if errors.Is(err, flag.ErrHelp) {
		a.printCmdHelp(fs)
		return ExitOK, false
	}
	return a.usageErr(err.Error()), false
}

// groupHelp answers `ssha audit --help` and its siblings. A command with
// subcommands dispatches on its first argument, so a request for help arrives
// looking like a subcommand name and would be reported as an unknown one.
func (a *App) groupHelp(cmd, usage string, args []string) bool {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintf(a.Stdout, "ssha %s\n\n%s\n", cmd, usage)
		return true
	}
	return false
}

// printCmdHelp lays the flags out itself rather than calling PrintDefaults: the
// standard library prints a single dash, which disagrees with the rest of this
// tool's help, and it has no way to keep a flag out of one command's listing.
func (a *App) printCmdHelp(fs *flag.FlagSet) {
	type row struct{ left, usage string }
	var rows []row
	width := 0
	fs.VisitAll(func(f *flag.Flag) {
		if a.shared[f.Name] {
			return
		}
		arg, usage := flag.UnquoteUsage(f)
		// -c is a one letter flag, and nobody writes --c.
		left := "--" + f.Name
		if len(f.Name) == 1 {
			left = "-" + f.Name
		}
		if arg != "" {
			left += " " + arg
		}
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
			if arg == "string" {
				usage += fmt.Sprintf(" (default %q)", f.DefValue)
			} else {
				usage += fmt.Sprintf(" (default %s)", f.DefValue)
			}
		}
		rows = append(rows, row{left, usage})
		width = max(width, len(left))
	})

	fmt.Fprintf(a.Stdout, "ssha %s [flags]\n\n", a.cmd)
	if len(rows) == 0 {
		fmt.Fprint(a.Stdout, "This command takes no flags of its own.\n")
	} else {
		fmt.Fprint(a.Stdout, "Flags:\n")
		for _, r := range rows {
			fmt.Fprintf(a.Stdout, "  %-*s   %s\n", width, r.left, r.usage)
		}
	}
	fmt.Fprint(a.Stdout, "\nEvery command also takes: -c/--config --json --no-prompt --reveal\n")
	fmt.Fprint(a.Stdout, "Run `ssha help` for the list of commands.\n")
}

// splitHost parses args where flags may appear both before and after a single
// host positional, e.g. `run --json web-1 --cwd /srv -- ls -la`. Parsing stops
// at the first non-flag token after the host, which begins the command tail.
func splitHost(fs *flag.FlagSet, args []string) (host string, tail []string, err error) {
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return "", nil, nil
	}
	host = pos[0]
	if err := fs.Parse(pos[1:]); err != nil {
		return "", nil, err
	}
	return host, fs.Args(), nil
}

// positionals parses flags interspersed with positional arguments, accepting
// at most n of them (n <= 0 means unlimited).
// positionals parses the positional arguments of a command, allowing flags
// before and after them. It reports errors the way the rest of the CLI does, so
// that --help is answered here too rather than being reported as a usage error.
func (a *App) positionals(fs *flag.FlagSet, args []string, n int) ([]string, int, bool) {
	pos, err := positionals(fs, args, n)
	if code, ok := a.parseErr(fs, err); !ok {
		return nil, code, false
	}
	return pos, 0, true
}

func positionals(fs *flag.FlagSet, args []string, n int) ([]string, error) {
	var pos []string
	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			return nil, err
		}
		got := fs.Args()
		if len(got) == 0 {
			break
		}
		if n > 0 && len(pos) >= n {
			return nil, fmt.Errorf("unexpected extra argument %q", got[0])
		}
		pos = append(pos, got[0])
		remaining = got[1:]
	}
	return pos, nil
}

// commandFrom joins the trailing command words, dropping a leading "--"
// separator so `ssha run web-1 -- ls -la` yields exactly `ls -la`.
func commandFrom(args []string) string {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	return strings.Join(args, " ")
}

// kvFlag collects repeated KEY=VALUE flags.
type kvFlag map[string]string

func (k *kvFlag) String() string { return "" }

func (k *kvFlag) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("expected KEY=VALUE, got %q", v)
	}
	if *k == nil {
		*k = map[string]string{}
	}
	(*k)[v[:i]] = v[i+1:]
	return nil
}
