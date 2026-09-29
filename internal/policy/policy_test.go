package policy

import (
	"strings"
	"testing"

	"ssha/internal/config"
)

func compile(t *testing.T, spec config.Spec) *Compiled {
	t.Helper()
	c, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile(%+v): %v", spec, err)
	}
	return c
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name    string
		spec    config.Spec
		command string
		allowed bool
		rule    string // substring expected in Reason when denied
	}{
		{
			name:    "allow mode permits anything not denied",
			spec:    config.Spec{Mode: config.ModeAllow},
			command: "curl https://example.com",
			allowed: true,
		},
		{
			name:    "allow mode still honours the deny list",
			spec:    config.Spec{Mode: config.ModeAllow, Deny: []string{`curl`}},
			command: "curl https://example.com",
			allowed: false,
			rule:    "deny rule",
		},
		{
			name:    "readonly permits an allow listed command",
			spec:    config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}},
			command: "ls -la /var/log",
			allowed: true,
		},
		{
			name:    "readonly rejects anything else",
			spec:    config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}},
			command: "cat /etc/shadow",
			allowed: false,
			rule:    "not in the allow list",
		},
		{
			name:    "readonly allow entries are anchored at the start",
			spec:    config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}},
			command: "sudo ls /root",
			allowed: false,
			rule:    "not in the allow list",
		},
		{
			name:    "readonly deny beats allow",
			spec:    config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}, Deny: []string{`ls\s+/root`}},
			command: "ls /root",
			allowed: false,
			rule:    "deny rule",
		},
		{
			name:    "deny mode blocks even allow listed commands",
			spec:    config.Spec{Mode: config.ModeDeny, Allow: []string{`^ls\b`}},
			command: "ls",
			allowed: false,
			rule:    "deny",
		},
		{
			name:    "unknown mode fails closed",
			spec:    config.Spec{Mode: "whatever"},
			command: "ls",
			allowed: false,
			rule:    "unknown policy mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := compile(t, tc.spec).Decide(tc.command)
			if d.Allowed != tc.allowed {
				t.Fatalf("Decide(%q).Allowed = %v, want %v (reason: %s)", tc.command, d.Allowed, tc.allowed, d.Reason)
			}
			if !tc.allowed && tc.rule != "" && !strings.Contains(d.Reason, tc.rule) {
				t.Errorf("Reason = %q, want it to contain %q", d.Reason, tc.rule)
			}
		})
	}
}

func TestBaselineDenyIsAlwaysApplied(t *testing.T) {
	destructive := []string{
		"rm -rf /",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"mkfs.ext4 /dev/nvme0n1",
		":(){ :|:& };:",
		"shutdown -h now",
		"> /etc/passwd",
		"chmod -R 777 /",
	}
	c := compile(t, config.Spec{Mode: config.ModeAllow})
	for _, cmd := range destructive {
		t.Run(cmd, func(t *testing.T) {
			if d := c.Decide(cmd); d.Allowed {
				t.Errorf("Decide(%q) was allowed; the baseline deny list should block it", cmd)
			}
		})
	}
}

func TestDisableBaseline(t *testing.T) {
	c := compile(t, config.Spec{Mode: config.ModeAllow, DisableBaseline: true})
	if d := c.Decide("mkfs.ext4 /dev/sda"); !d.Allowed {
		t.Errorf("with disable_baseline the command should be allowed, got %s", d.Reason)
	}
}

func TestBaselineDenyDoesNotLeakBetweenCompiles(t *testing.T) {
	// Compile mutates nothing global: a later permissive spec must not inherit
	// deny rules from an earlier one.
	first := compile(t, config.Spec{Mode: config.ModeAllow, Deny: []string{`^curl`}})
	if first.Decide("curl x").Allowed {
		t.Fatal("expected the custom deny rule to apply")
	}
	second := compile(t, config.Spec{Mode: config.ModeAllow})
	if !second.Decide("curl x").Allowed {
		t.Fatal("custom deny rule leaked into an unrelated policy")
	}
}

func TestDecidePath(t *testing.T) {
	tests := []struct {
		name    string
		spec    config.Spec
		path    string
		write   bool
		allowed bool
	}{
		{"allow mode permits reads", config.Spec{Mode: config.ModeAllow}, "/etc/hosts", false, true},
		{"allow mode permits writes", config.Spec{Mode: config.ModeAllow}, "/tmp/x", true, true},
		{"readonly mode permits reads", config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls`}}, "/etc/hosts", false, true},
		{"readonly mode forbids writes", config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls`}}, "/tmp/x", true, false},
		{"deny mode forbids reads", config.Spec{Mode: config.ModeDeny}, "/etc/hosts", false, false},
		{"deny_paths applies to reads", config.Spec{Mode: config.ModeAllow, DenyPaths: []string{`^/etc/shadow$`}}, "/etc/shadow", false, false},
		{"deny_paths applies to writes", config.Spec{Mode: config.ModeAllow, DenyPaths: []string{`\.ssh/`}}, "/root/.ssh/authorized_keys", true, false},
		{"deny_paths does not over match", config.Spec{Mode: config.ModeAllow, DenyPaths: []string{`^/etc/shadow$`}}, "/etc/shadow.bak", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := compile(t, tc.spec).DecidePath(tc.path, tc.write)
			if d.Allowed != tc.allowed {
				t.Fatalf("DecidePath(%q, write=%v).Allowed = %v, want %v (%s)", tc.path, tc.write, d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

func TestCompileRejectsInvalidRegex(t *testing.T) {
	if _, err := Compile(config.Spec{Mode: config.ModeAllow, Deny: []string{`([unclosed`}}); err == nil {
		t.Fatal("expected an error for an invalid deny pattern")
	}
	if _, err := Compile(config.Spec{Mode: config.ModeReadonly, Allow: []string{`*bad`}}); err == nil {
		t.Fatal("expected an error for an invalid allow pattern")
	}
}

func TestSetForUnknownHostFailsClosed(t *testing.T) {
	set := Set{}
	if d := set.For("ghost").Decide("ls"); d.Allowed {
		t.Fatal("an unknown host must default to deny")
	}
}

func TestMultiLineCommandsAreMatched(t *testing.T) {
	c := compile(t, config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}})
	if d := c.Decide("ls -la\nrm -rf /"); d.Allowed {
		t.Fatal("a multiline command should not slip through the allow list")
	}
}

func TestReadonlyRejectsShellMetacharacters(t *testing.T) {
	// Every one of these starts with an allowed command but chains a second one.
	smuggled := []string{
		"ls; rm -rf /tmp/x",
		"ls && cat /etc/shadow",
		"ls || curl http://evil",
		"ls | xargs rm -rf /tmp/x",
		"ls > /etc/passwd",
		"ls `id`",
		"ls $(id)",
		"ls -la\nrm -rf /tmp/x",
	}
	c := compile(t, config.Spec{Mode: config.ModeReadonly, Allow: []string{`^ls\b`}})
	for _, cmd := range smuggled {
		t.Run(cmd, func(t *testing.T) {
			d := c.Decide(cmd)
			if d.Allowed {
				t.Fatalf("Decide(%q) was allowed", cmd)
			}
			if !strings.Contains(d.Reason, "metacharacter") && !strings.Contains(d.Reason, "deny rule") {
				t.Errorf("Reason = %q, want it to mention metacharacters or a deny rule", d.Reason)
			}
		})
	}
}

func TestReadonlyAllowsPlainArguments(t *testing.T) {
	// A lone $ and ordinary punctuation must keep working: readonly hosts are
	// the common case and must remain usable.
	c := compile(t, config.Spec{Mode: config.ModeReadonly, Allow: []string{`^echo\b`, `^journalctl\b`}})
	for _, cmd := range []string{
		"echo FOO=$FOO",
		"echo hello, world",
		"journalctl -u nginx --since '2 hours ago'",
	} {
		t.Run(cmd, func(t *testing.T) {
			if d := c.Decide(cmd); !d.Allowed {
				t.Fatalf("Decide(%q) was denied: %s", cmd, d.Reason)
			}
		})
	}
}

func TestAllowShellMetacharsOptIn(t *testing.T) {
	c := compile(t, config.Spec{
		Mode:                config.ModeReadonly,
		Allow:               []string{`^journalctl\b`},
		AllowShellMetachars: true,
	})
	if d := c.Decide("journalctl -n 50 | tail -5"); !d.Allowed {
		t.Fatalf("with allow_shell_metacharacters the pipeline should be allowed: %s", d.Reason)
	}
}
