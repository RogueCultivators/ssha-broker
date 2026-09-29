package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ssha/internal/config"
	"ssha/internal/policy"
	"ssha/internal/sshx"
)

// writeTestKey creates a throwaway private key so the auth layer gets past key
// parsing and the test can reach the dial failure it actually cares about.
func writeTestKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func host(addr string, port int, user string) *config.Host {
	return &config.Host{Name: "prod", Addr: addr, Port: port, User: user}
}

func TestRedactorHidesAddressAndUser(t *testing.T) {
	r := newRedactor(host("10.0.0.10", 2222, "deploy"), nil, nil)
	if r == nil {
		t.Fatal("expected a redactor")
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"address with port", "connecting to 10.0.0.10:2222 now", "connecting to <host> now"},
		{"bare address", "host 10.0.0.10 is up", "host <host> is up"},
		{"user name", "logged in as deploy", "logged in as <user>"},
		{"user inside a path", "/home/deploy/app/config.yaml", "/home/<user>/app/config.yaml"},
		{"user plus address", "deploy@10.0.0.10:2222", "<user>@<host>"},
		{"unrelated text is untouched", "load average: 0.42", "load average: 0.42"},
		{"a longer word is not a user match", "the deployer service", "the deployer service"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.apply(tc.in); got != tc.want {
				t.Errorf("apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactorPrefersTheLongestForm(t *testing.T) {
	// "10.0.0.10:22" must not decay into "<host>:22".
	r := newRedactor(host("10.0.0.10", 22, "root"), nil, nil)

	got := r.apply("ssh root@10.0.0.10:22")
	if got != "ssh <user>@<host>" {
		t.Fatalf("apply = %q, want %q", got, "ssh <user>@<host>")
	}
	if strings.Contains(got, ":22") {
		t.Error("the port survived redaction")
	}
}

func TestRedactorDoesNotScrubTheAlias(t *testing.T) {
	// When the name is also the address, the agent already knows it from
	// ssh_list_hosts, so scrubbing it would only add noise. The user name is
	// still hidden.
	h := &config.Host{Name: "prod.internal.example.com", User: "deploy"}
	r := newRedactor(h, nil, nil)
	if got := r.apply("resolved prod.internal.example.com"); got != "resolved prod.internal.example.com" {
		t.Errorf("the alias was scrubbed: %q", got)
	}
	if got := r.apply("logged in as deploy"); got != "logged in as <user>" {
		t.Errorf("apply = %q, want the user to be hidden", got)
	}
}

func TestRedactorIncludesTheJumpHost(t *testing.T) {
	jump := &config.Host{Name: "bastion", Addr: "bastion.example.com", Port: 22, User: "jump"}
	target := &config.Host{Name: "app", Addr: "10.1.0.20", Port: 22, User: "deploy", ProxyJump: "bastion"}

	r := newRedactor(target, jump, nil)
	got := r.apply("bastion.example.com as jump then 10.1.0.20 as deploy")
	if got != "<host> as <user> then <host> as <user>" {
		t.Fatalf("apply = %q", got)
	}
}

func TestRedactorExtraPatterns(t *testing.T) {
	extra := regexp.MustCompile(`\bSECRET-[A-Z0-9]+\b`)
	r := newRedactor(host("10.0.0.10", 22, "deploy"), nil, []*regexp.Regexp{extra})
	got := r.apply("token=SECRET-ABC123 host=10.0.0.10")
	if got != "token=<redacted> host=<host>" {
		t.Fatalf("apply = %q", got)
	}
}

func TestNilRedactorIsANoOp(t *testing.T) {
	var r *redactor
	if got := r.apply("nothing changes"); got != "nothing changes" {
		t.Errorf("apply = %q", got)
	}
}

func TestRedactorWithNothingToHideIsNil(t *testing.T) {
	// No address beyond the alias and no user name: nothing to scrub.
	if r := newRedactor(&config.Host{Name: "prod"}, nil, nil); r != nil {
		t.Errorf("expected no redactor, got %+v", r.rules)
	}
}

// ---------------------------------------------------------------------------
// disclosure
// ---------------------------------------------------------------------------

func loadBroker(t *testing.T, body string, reveal bool) *Broker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policies, err := policy.NewSet(cfg)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	// A pool is included so this helper cannot surprise a future test that
	// reaches the execution path with a nil dereference.
	b := &Broker{cfg: cfg, policies: policies, pool: sshx.NewPool(time.Minute), reveal: reveal}
	b.buildRedactors()
	return b
}

const disclosureConfig = `
hosts:
  - name: public-host
    addr: 10.0.0.10
    user: deploy
    description: fully disclosed
    tags: [prod]
    work_dir: /srv/app
    auth: {type: key, key_path: /tmp/key}
    policy:
      mode: readonly
      allow_commands: ['^ls\b']
      disclosure: full
  - name: alias-host
    addr: 10.0.0.20
    user: deploy
    description: identity hidden
    tags: [prod, db]
    work_dir: /srv/db
    proxy_jump: public-host
    auth: {type: password, password_env: DB_PW}
    policy:
      mode: readonly
      allow_commands: ['^ls\b']
      disclosure: alias
  - name: blind-host
    addr: 10.0.0.30
    user: root
    description: everything hidden
    tags: [secret]
    auth: {type: key, key_path: /tmp/key}
    policy:
      mode: deny
      disclosure: blind
`

func TestHostInfoDisclosureLevels(t *testing.T) {
	b := loadBroker(t, disclosureConfig, false)

	full := b.Hosts(nil, []string{"public-host"}, false)[0]
	if full.Addr != "10.0.0.10:22" || full.User != "deploy" || full.Auth != "key" || full.WorkDir != "/srv/app" {
		t.Errorf("full disclosure hid something: %+v", full)
	}

	alias := b.Hosts(nil, []string{"alias-host"}, false)[0]
	if alias.Addr != "" || alias.User != "" || alias.Auth != "" || alias.ProxyJump != "" || alias.WorkDir != "" {
		t.Errorf("alias disclosure leaked identity: %+v", alias)
	}
	if alias.Description != "identity hidden" || len(alias.Tags) != 2 || alias.PolicyMode != config.ModeReadonly {
		t.Errorf("alias disclosure hid too much: %+v", alias)
	}
	if len(alias.Allow) != 1 {
		t.Errorf("alias disclosure should keep the allow list: %+v", alias.Allow)
	}

	blind := b.Hosts(nil, []string{"blind-host"}, false)[0]
	if blind.Addr != "" || blind.User != "" || blind.Description != "" || len(blind.Tags) != 0 || len(blind.Allow) != 0 {
		t.Errorf("blind disclosure leaked detail: %+v", blind)
	}
	if blind.PolicyMode != config.ModeDeny || blind.Timeout == "" || blind.MaxOutputSize == 0 {
		t.Errorf("blind disclosure must still describe the policy: %+v", blind)
	}
}

func TestRevealBypassesDisclosure(t *testing.T) {
	b := loadBroker(t, disclosureConfig, true)
	alias := b.Hosts(nil, []string{"alias-host"}, false)[0]
	if alias.Addr != "10.0.0.20:22" || alias.User != "deploy" {
		t.Errorf("--reveal should show the real details: %+v", alias)
	}
}

func TestDisclosureAppliesToDescribeHost(t *testing.T) {
	b := loadBroker(t, disclosureConfig, false)
	info, err := b.DescribeHost("alias-host")
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != "" || info.User != "" {
		t.Errorf("DescribeHost leaked identity: %+v", info)
	}
}

// selfTestConfig points at a closed port so the dial fails immediately, which
// is the path where identity is easiest to leak by accident.
func selfTestConfig(t *testing.T, disclosure string, redact bool) string {
	t.Helper()
	return fmt.Sprintf(`
hosts:
  - name: hidden
    addr: 127.0.0.1
    port: 1
    user: svc-ops
    auth: {type: key, key_path: %s}
    host_key: {insecure: true}
    policy:
      mode: allow
      disclosure: %s
      redact_output: %t
      timeout: 500ms
`, writeTestKey(t), disclosure, redact)
}

func TestSelfTestHidesIdentityOnFailure(t *testing.T) {
	b := loadBroker(t, selfTestConfig(t, config.DisclosureAlias, true), false)
	res := b.Test(context.Background(), "hidden", "")
	if res.OK {
		t.Fatal("the dial was expected to fail")
	}
	if res.Addr != "" || res.User != "" || res.Auth != "" || res.Via != "" {
		t.Errorf("identity leaked on the failure path: %+v", res)
	}
	if strings.Contains(res.Error, "127.0.0.1") {
		t.Errorf("the error leaked the address: %s", res.Error)
	}
	if !strings.Contains(res.Error, "<host>") {
		t.Errorf("expected a placeholder in the error, got: %s", res.Error)
	}
}

func TestSelfTestAtFullDisclosureKeepsIdentity(t *testing.T) {
	b := loadBroker(t, selfTestConfig(t, config.DisclosureFull, false), false)
	res := b.Test(context.Background(), "hidden", "")
	if res.Addr != "127.0.0.1:1" || res.User != "svc-ops" || res.Auth != "key" {
		t.Errorf("full disclosure should keep identity: %+v", res)
	}
	if strings.Contains(res.Error, "<host>") {
		t.Errorf("redaction is off for this host, so the error should be raw: %s", res.Error)
	}
}

func TestRevealRestoresTheSelfTest(t *testing.T) {
	b := loadBroker(t, selfTestConfig(t, config.DisclosureAlias, true), true)
	res := b.Test(context.Background(), "hidden", "")
	if res.Addr != "127.0.0.1:1" || res.User != "svc-ops" {
		t.Errorf("--reveal should show identity: %+v", res)
	}
	if strings.Contains(res.Error, "<host>") {
		t.Errorf("--reveal should disable redaction: %s", res.Error)
	}
}
