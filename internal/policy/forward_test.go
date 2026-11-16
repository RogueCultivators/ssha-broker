package policy

import (
	"strings"
	"testing"

	"ssha/internal/config"
)

func TestDecideRemoteForward(t *testing.T) {
	c := compile(t, config.Spec{
		Mode:                config.ModeAllow,
		AllowForwards:       []string{"10.0.0.12:5432"},
		AllowRemoteForwards: []string{"127.0.0.1:8000", "*.local:9000"},
		DenyRemoteForwards:  []string{"127.0.0.1:22"},
	})

	tests := []struct {
		name        string
		destination string
		allowed     bool
		reason      string
	}{
		{name: "an exact allow entry permits the local destination", destination: "127.0.0.1:8000", allowed: true},
		{name: "a host wildcard works", destination: "cache.local:9000", allowed: true},
		{name: "deny wins over allow", destination: "127.0.0.1:22", reason: "deny_remote_forwards"},
		{name: "an unlisted destination is denied", destination: "127.0.0.1:8001", reason: "allow_remote_forwards"},
		// The two directions are separate allowlists: a local forward target
		// must not become a remote forward destination, or vice versa.
		{name: "allow_forwards does not authorize remote", destination: "10.0.0.12:5432", reason: "allow_remote_forwards"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := c.DecideRemoteForward(tc.destination)
			if d.Allowed != tc.allowed {
				t.Fatalf("DecideRemoteForward(%q) = %+v, want allowed=%v", tc.destination, d, tc.allowed)
			}
			if tc.reason != "" && !strings.Contains(d.Reason, tc.reason) {
				t.Errorf("reason = %q, want it to contain %q", d.Reason, tc.reason)
			}
		})
	}
	if d := c.DecideForward("127.0.0.1:8000"); d.Allowed {
		t.Fatalf("allow_remote_forwards authorized a local forward: %+v", d)
	}

	for _, mode := range []string{config.ModeReadonly, config.ModeDeny} {
		off := compile(t, config.Spec{Mode: mode, AllowRemoteForwards: []string{"*:*"}})
		if d := off.DecideRemoteForward("127.0.0.1:8000"); d.Allowed {
			t.Errorf("mode %s allowed a remote forward: %+v", mode, d)
		}
	}
	if d := compile(t, config.Spec{Mode: config.ModeAllow}).DecideRemoteForward("127.0.0.1:8000"); d.Allowed {
		t.Errorf("remote forwarding was on without an allow list: %+v", d)
	}
}

func TestDecideForward(t *testing.T) {
	tests := []struct {
		name        string
		spec        config.Spec
		destination string
		allowed     bool
		reason      string
		rule        string
	}{
		{
			name:        "an exact allow entry permits the destination",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"10.0.0.12:5432"}},
			destination: "10.0.0.12:5432",
			allowed:     true,
			rule:        "10.0.0.12:5432",
		},
		{
			name:        "matching is case insensitive",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"DB.Internal:3306"}},
			destination: "db.internal:3306",
			allowed:     true,
		},
		{
			name:        "a wildcard port matches any port",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"db.internal:*"}},
			destination: "db.internal:6379",
			allowed:     true,
		},
		{
			name:        "a host wildcard matches a suffix",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"*.internal:5432"}},
			destination: "cache.internal:5432",
			allowed:     true,
		},
		{
			name:        "? matches exactly one character",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"10.0.0.1?:5432"}},
			destination: "10.0.0.12:5432",
			allowed:     true,
		},
		{
			name:        "an IPv6 destination keeps its brackets",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"[::1]:5432"}},
			destination: "[::1]:5432",
			allowed:     true,
		},
		{
			name:        "deny wins over allow",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"10.0.0.12:*"}, DenyForwards: []string{"10.0.0.12:6379"}},
			destination: "10.0.0.12:6379",
			reason:      "deny_forwards",
			rule:        "10.0.0.12:6379",
		},
		{
			name:        "forwarding is off without an allow list",
			spec:        config.Spec{Mode: config.ModeAllow, DenyForwards: []string{"169.254.169.254:*"}},
			destination: "10.0.0.12:5432",
			reason:      "not enabled",
		},
		{
			name:        "readonly hosts never forward",
			spec:        config.Spec{Mode: config.ModeReadonly, Allow: []string{"^ls"}, AllowForwards: []string{"*:*"}},
			destination: "10.0.0.12:5432",
			reason:      "readonly",
		},
		{
			name:        "deny mode blocks forwarding",
			spec:        config.Spec{Mode: config.ModeDeny, AllowForwards: []string{"*:*"}},
			destination: "10.0.0.12:5432",
			reason:      "mode is deny",
		},
		{
			name:        "a destination outside the list is denied",
			spec:        config.Spec{Mode: config.ModeAllow, AllowForwards: []string{"10.0.0.12:5432"}},
			destination: "10.0.0.12:5433",
			reason:      "not in the host's allow_forwards",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := compile(t, tc.spec)
			d := c.DecideForward(tc.destination)
			if d.Allowed != tc.allowed {
				t.Fatalf("DecideForward(%q) = %+v, want allowed=%v", tc.destination, d, tc.allowed)
			}
			if tc.reason != "" && !strings.Contains(d.Reason, tc.reason) {
				t.Errorf("reason = %q, want it to contain %q", d.Reason, tc.reason)
			}
			if tc.rule != "" && d.Rule != tc.rule {
				t.Errorf("rule = %q, want %q", d.Rule, tc.rule)
			}
		})
	}
}
