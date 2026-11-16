package config

import (
	"strings"
	"testing"
)

func TestValidateForwardPatterns(t *testing.T) {
	tests := []struct {
		pattern string
		wantErr string
	}{
		{pattern: "10.0.0.12:5432"},
		{pattern: "db.internal:3306"},
		{pattern: "*.internal:6379"},
		{pattern: "10.0.0.*:5432"},
		{pattern: "10.0.0.12:*"},
		{pattern: "*:*"},
		{pattern: "[2001:db8::1]:5432"},
		{pattern: "[::1]:*"},
		{pattern: "", wantErr: "empty"},
		{pattern: " 10.0.0.12:5432", wantErr: "whitespace"},
		{pattern: "10.0.0.12", wantErr: "host:port"},
		{pattern: ":5432", wantErr: "empty host"},
		{pattern: "10.0.0.12:0", wantErr: "1-65535"},
		{pattern: "10.0.0.12:65536", wantErr: "1-65535"},
		{pattern: "10.0.0.12:redis", wantErr: "1-65535"},
		{pattern: "user@10.0.0.12:5432", wantErr: "not allowed"},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			err := validateForwardPatterns("host \"web\"", []string{tc.pattern}, nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateForwardPatterns(%q): %v", tc.pattern, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateForwardPatterns(%q) = %v, want an error containing %q", tc.pattern, err, tc.wantErr)
			}
		})
	}
}

func TestLoadRejectsABadForwardPattern(t *testing.T) {
	body := minimalHost + "    policy:\n      allow_forwards: [\"10.0.0.12\"]\n"
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "allow_forwards") {
		t.Fatalf("got %v, want an allow_forwards error", err)
	}
}

func TestValidateRemoteForwardPatterns(t *testing.T) {
	if err := validateRemoteForwardPatterns("host \"web\"", []string{"127.0.0.1:8000", "[::1]:*"}, []string{"127.0.0.1:22"}); err != nil {
		t.Fatalf("valid remote patterns were rejected: %v", err)
	}
	err := validateRemoteForwardPatterns("host \"web\"", []string{"127.0.0.1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "allow_remote_forwards") {
		t.Fatalf("got %v, want an allow_remote_forwards error", err)
	}
	err = validateRemoteForwardPatterns("host \"web\"", nil, []string{"127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "deny_remote_forwards") {
		t.Fatalf("got %v, want a deny_remote_forwards error", err)
	}
}

func TestLoadRejectsABadRemoteForwardPattern(t *testing.T) {
	body := minimalHost + "    policy:\n      allow_remote_forwards: [\"127.0.0.1\"]\n"
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "allow_remote_forwards") {
		t.Fatalf("got %v, want an allow_remote_forwards error", err)
	}
}

func TestRemoteForwardListsMergeLikeTheOtherLists(t *testing.T) {
	base := Spec{AllowRemoteForwards: []string{"127.0.0.1:8000"}, DenyRemoteForwards: []string{"127.0.0.1:22"}}

	keep := Merge(base, &Spec{})
	if len(keep.AllowRemoteForwards) != 1 || len(keep.DenyRemoteForwards) != 1 {
		t.Fatalf("a nil override did not keep the lists: %+v", keep)
	}

	off := Merge(base, &Spec{AllowRemoteForwards: []string{}})
	if len(off.AllowRemoteForwards) != 0 {
		t.Fatalf("an explicit empty allow_remote_forwards did not override: %+v", off)
	}

	replaced := Merge(base, &Spec{AllowRemoteForwards: []string{"127.0.0.1:9000"}})
	if len(replaced.AllowRemoteForwards) != 1 || replaced.AllowRemoteForwards[0] != "127.0.0.1:9000" {
		t.Fatalf("allow_remote_forwards was not replaced: %+v", replaced)
	}
	if len(replaced.DenyRemoteForwards) != 1 {
		t.Fatalf("deny_remote_forwards should have been inherited: %+v", replaced)
	}
}

func TestForwardListsMergeLikeTheOtherLists(t *testing.T) {
	base := Spec{AllowForwards: []string{"10.0.0.12:5432"}, DenyForwards: []string{"169.254.169.254:*"}}

	keep := Merge(base, &Spec{})
	if len(keep.AllowForwards) != 1 || len(keep.DenyForwards) != 1 {
		t.Fatalf("a nil override did not keep the lists: %+v", keep)
	}

	// An explicit empty list disables forwarding inherited from the global
	// policy; it is different from leaving the key out.
	off := Merge(base, &Spec{AllowForwards: []string{}})
	if len(off.AllowForwards) != 0 {
		t.Fatalf("an explicit empty allow_forwards did not override: %+v", off)
	}

	replaced := Merge(base, &Spec{AllowForwards: []string{"db.internal:*"}})
	if len(replaced.AllowForwards) != 1 || replaced.AllowForwards[0] != "db.internal:*" {
		t.Fatalf("allow_forwards was not replaced: %+v", replaced)
	}
	if len(replaced.DenyForwards) != 1 {
		t.Fatalf("deny_forwards should have been inherited: %+v", replaced)
	}
}
