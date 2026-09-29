// Package ui serves a local, single-page editor for the ssha configuration.
//
// It exists because the configuration is the trust boundary: an operator needs
// to see what an agent will be told, and editing YAML by hand is a poor way to
// discover that a host has no host key pinned or no password source.
//
// The server binds to loopback only and requires a per-run token, so a page in
// another tab cannot drive it.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/config"
	"ssha/internal/sshconfig"
	"ssha/internal/sshx"

	"golang.org/x/crypto/ssh"
)

//go:embed index.html
var assets embed.FS

// Options configures the editor.
type Options struct {
	ConfigPath string
	Addr       string
	Version    string
	// Open tries to launch the operator's browser.
	Open bool
	// TokenFile keeps the access token across restarts so a bookmarked URL keeps
	// working. Without it the token is fresh every run. The file is created with
	// mode 0600 if it does not exist.
	TokenFile string
}

// Run serves the editor until ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:8770"
	}
	if err := requireLoopback(addr); err != nil {
		return err
	}

	token, err := loadToken(opts.TokenFile)
	if err != nil {
		return err
	}
	s := &server{cfgPath: opts.ConfigPath, token: token, version: opts.Version}
	if err := s.openBroker(); err != nil {
		return err
	}
	defer s.close()

	page, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	})
	mux.Handle("/api/state", s.auth(http.HandlerFunc(s.handleState)))
	mux.Handle("/api/hosts", s.auth(http.HandlerFunc(s.handleHosts)))
	mux.Handle("/api/hosts/", s.auth(http.HandlerFunc(s.handleHost)))
	mux.Handle("/api/secret", s.auth(http.HandlerFunc(s.handleSecret)))
	mux.Handle("/api/test", s.auth(http.HandlerFunc(s.handleTest)))
	mux.Handle("/api/hostkey", s.auth(http.HandlerFunc(s.handleHostKey)))
	mux.Handle("/api/audit", s.auth(http.HandlerFunc(s.handleAudit)))
	mux.Handle("/api/sshconfig", s.auth(http.HandlerFunc(s.handleSSHConfig)))
	mux.Handle("/api/sshconfig/import", s.auth(http.HandlerFunc(s.handleSSHConfigImport)))

	// Bind before announcing anything: printing a URL for a port we failed to
	// take would send the operator to whatever else is listening there.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("无法监听 %s：%w", addr, err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	url := "http://" + ln.Addr().String() + "/?token=" + token
	fmt.Fprintf(os.Stderr,
		"ssha 配置界面\n"+
			"  配置文件：%s\n"+
			"\n"+
			"  用浏览器打开下面这条地址（token 必须带，每次启动都会变）：\n"+
			"    %s\n\n", s.cfgPath, url)
	if opts.Open {
		openBrowser(url)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// loadToken returns a stable token when a file is configured, creating it on
// first use, and a fresh one otherwise.
func loadToken(path string) (string, error) {
	if path == "" {
		return newToken()
	}
	path = config.ExpandHome(path)
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}
	return token, nil
}

func newToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" || host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("拒绝把界面绑到 %s：那等于让网络上的任何人改你的 ssha 配置。请用 127.0.0.1，或者走 SSH 端口转发", addr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

type server struct {
	cfgPath string
	token   string
	version string

	mu sync.Mutex
	b  *broker.Broker
}

func (s *server) openBroker() error {
	// The editor is the operator's own console, so it sees real addresses and
	// unredacted output: it is the thing they are configuring.
	b, err := broker.OpenWithOptions(s.cfgPath, broker.Options{Reveal: true})
	if err != nil {
		return err
	}
	s.b = b
	return nil
}

func (s *server) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b != nil {
		_ = s.b.Close()
		s.b = nil
	}
}

// reload re-reads the config so the next request sees the edit.
func (s *server) reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := broker.OpenWithOptions(s.cfgPath, broker.Options{Reveal: true})
	if err != nil {
		return err
	}
	if s.b != nil {
		_ = s.b.Close()
	}
	s.b = b
	return nil
}

func (s *server) broker() *broker.Broker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b
}

// auth enforces the per-run token. A custom header also means a cross-origin
// page cannot reach the API without a CORS preflight we never approve.
func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		got := r.Header.Get("X-SSHA-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "bad or missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

// hostView is a config host plus what the editor needs beyond the file: the
// policy that will actually apply, and the problems worth flagging.
type hostView struct {
	config.Host
	Effective     config.Spec `json:"effective_policy"`
	Warnings      []string    `json:"warnings,omitempty"`
	EffectiveMode string      `json:"effective_mode"`
	// Whether the configured secret file exists and is non-empty. The secret
	// itself is never part of any response.
	PasswordReady   bool `json:"password_ready"`
	PassphraseReady bool `json:"passphrase_ready"`
}

type statePayload struct {
	ConfigPath string      `json:"config_path"`
	AuditPath  string      `json:"audit_path"`
	SecretsDir string      `json:"secrets_dir"`
	Version    string      `json:"version"`
	Global     config.Spec `json:"global_policy"`
	Defaults   config.Spec `json:"defaults"`
	Hosts      []hostView  `json:"hosts"`
}

func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	b := s.broker()
	cfg := b.Config()
	out := statePayload{
		ConfigPath: s.cfgPath,
		AuditPath:  b.AuditPath(),
		SecretsDir: config.SecretsDir(s.cfgPath),
		Version:    s.version,
		Global:     cfg.GlobalPolicy(),
		Defaults:   cfg.Defaults,
	}
	for i := range cfg.Hosts {
		h := cfg.Hosts[i]
		spec := cfg.EffectivePolicy(&h)
		out.Hosts = append(out.Hosts, hostView{
			Host:            h,
			Effective:       spec,
			EffectiveMode:   spec.Mode,
			Warnings:        hostWarnings(&h, spec),
			PasswordReady:   config.HasSecret(h.Auth.PasswordFile),
			PassphraseReady: config.HasSecret(h.Auth.PassphraseFile),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// hostWarnings flags the mistakes that silently make a host useless: no host
// key pinned, no password source, a host that would block every command.
func hostWarnings(h *config.Host, spec config.Spec) []string {
	var out []string
	if h.Auth.Type == "password" && h.Auth.PasswordEnv == "" && h.Auth.PasswordFile == "" {
		out = append(out, "密码没有来源：命令行会交互式提问，但 agent 走 MCP 时会直接失败。请填密码文件或密码环境变量。")
	}
	if h.Auth.Type == "key" && h.Auth.KeyPath == "" && h.Auth.KeyEnv == "" {
		out = append(out, "认证类型是私钥，但没有填私钥路径，也没有填私钥内容的环境变量。")
	}
	if len(h.HostKey.Fingerprints) == 0 && h.HostKey.KnownHosts == "" && !h.HostKey.Insecure {
		out = append(out, "没有钉主机密钥：默认会去读 ~/.ssh/known_hosts，里面没有这台机器就会被拒绝连接（可以用“扫描主机密钥”）。")
	}
	if h.HostKey.Insecure {
		out = append(out, "已打开 insecure：不校验服务器身份。仅测试用。")
	}
	if spec.Mode == config.ModeReadonly && len(spec.Allow) == 0 {
		out = append(out, "策略是 readonly 但白名单是空的，等于什么都跑不了。")
	}
	if spec.RedactOutput && spec.Disclosure == config.DisclosureFull {
		out = append(out, "遮蔽了输出里的地址，但身份可见度还是 full，主机清单里依然能看到地址。")
	}
	return out
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 POST"))
		return
	}
	var h config.Host
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&h); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid host payload: %w", err))
		return
	}
	if h.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("名称不能为空"))
		return
	}
	if err := config.UpsertHost(s.cfgPath, h); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := s.reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	slog.Info("config updated", "host", h.Name, "config", s.cfgPath)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": h.Name})
}

func (s *server) handleHost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	if name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("需要主机名称"))
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := config.DeleteHost(s.cfgPath, name); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		if err := s.reload(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		slog.Info("host removed", "host", name)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.Header().Set("Allow", "DELETE")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 DELETE"))
	}
}

// handleSecret stores or clears the password or passphrase for one host.
//
// Typing a secret in the editor means "use this", so storing one also clears a
// higher-precedence environment variable on that host. Leaving it would make
// the freshly typed secret silently useless, which is the worse surprise; the
// response says what was cleared so the editor can tell the operator.
func (s *server) handleSecret(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host  string `json:"host"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求格式不对：%w", err))
		return
	}
	kind := config.SecretKind(in.Kind)
	switch kind {
	case config.SecretPassword, config.SecretPassphrase:
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("kind 只能是 password 或 passphrase，收到 %q", in.Kind))
		return
	}
	current, err := s.broker().Config().Host(in.Host)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	updated := *current
	cleared := ""

	if in.Value == "" {
		if err := config.DeleteSecret(s.cfgPath, in.Host, kind); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("删除失败：%w", err))
			return
		}
		// Only forget a path that was ours; a hand-written path stays.
		ours := config.SecretPath(s.cfgPath, in.Host, kind)
		switch {
		case kind == config.SecretPassword && updated.Auth.PasswordFile == ours:
			updated.Auth.PasswordFile = ""
		case kind == config.SecretPassphrase && updated.Auth.PassphraseFile == ours:
			updated.Auth.PassphraseFile = ""
		}
	} else {
		path, err := config.WriteSecret(s.cfgPath, in.Host, kind, in.Value)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("保存失败：%w", err))
			return
		}
		if kind == config.SecretPassword {
			cleared = updated.Auth.PasswordEnv
			updated.Auth.PasswordEnv = ""
			updated.Auth.PasswordFile = path
		} else {
			cleared = updated.Auth.PassphraseEnv
			updated.Auth.PassphraseEnv = ""
			updated.Auth.PassphraseFile = path
		}
	}

	if err := config.UpsertHost(s.cfgPath, updated); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := s.reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	slog.Info("secret updated", "host", in.Host, "kind", kind, "stored", in.Value != "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"stored":      in.Value != "",
		"cleared_env": cleared,
		"path":        config.SecretPath(s.cfgPath, in.Host, kind),
	})
}

func (s *server) handleTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name  string `json:"name"`
		Probe string `json:"probe"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.broker().Test(ctx, in.Name, in.Probe))
}

func (s *server) handleHostKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Addr string `json:"addr"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Addr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("需要填地址"))
		return
	}
	if in.Port == 0 {
		in.Port = 22
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	keys, err := sshx.ScanHostKeys(ctx, net.JoinHostPort(in.Addr, strconv.Itoa(in.Port)), 10*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	type keyInfo struct {
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
		Line        string `json:"line"`
	}
	out := make([]keyInfo, 0, len(keys))
	for _, k := range keys {
		line := sshx.KnownHostsLine(net.JoinHostPort(in.Addr, strconv.Itoa(in.Port)), k)
		out = append(out, keyInfo{
			Type:        k.Type(),
			Fingerprint: ssh.FingerprintSHA256(k),
			Line:        line,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	records, err := s.broker().AuditQuery(audit.Filter{
		Host:     q.Get("host"),
		Decision: q.Get("decision"),
	}, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if records == nil {
		records = []audit.Record{} // an empty log is [], not null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_log": s.broker().AuditPath(),
		"records":   records,
		"count":     len(records),
	})
}

// ---------------------------------------------------------------------------
// importing ~/.ssh/config
// ---------------------------------------------------------------------------

// importCandidate is one Host block from the ssh config, ready to be checked.
type importCandidate struct {
	Alias     string   `json:"alias"`
	Addr      string   `json:"addr"`
	User      string   `json:"user,omitempty"`
	Port      int      `json:"port,omitempty"`
	Auth      string   `json:"auth"`
	ProxyJump string   `json:"proxy_jump,omitempty"`
	Source    string   `json:"source"`
	Exists    bool     `json:"exists"`
	Warnings  []string `json:"warnings,omitempty"`
}

func (s *server) importCandidates(file string) ([]importCandidate, []string, error) {
	if file == "" {
		file = sshconfig.DefaultPath()
	}
	file = config.ExpandHome(file)
	if file == "" {
		return nil, nil, errors.New("cannot locate ~/.ssh/config")
	}
	res, err := sshconfig.Parse(file)
	if err != nil {
		return nil, nil, err
	}
	converted := sshconfig.Convert(res.Hosts, sshconfig.ConvertOptions{PolicyMode: config.ModeDeny})
	cfg := s.broker().Config()

	out := make([]importCandidate, 0, len(converted))
	for _, c := range converted {
		h := c.Host
		_, existsErr := cfg.Host(h.Name)
		out = append(out, importCandidate{
			Alias:     h.Name,
			Addr:      h.Addr,
			User:      h.User,
			Port:      h.Port,
			Auth:      h.Auth.Type,
			ProxyJump: h.ProxyJump,
			Source:    c.Source,
			Exists:    existsErr == nil,
			Warnings:  c.Warnings,
		})
	}
	return out, res.Warnings, nil
}

func (s *server) handleSSHConfig(w http.ResponseWriter, r *http.Request) {
	candidates, warnings, err := s.importCandidates(r.URL.Query().Get("file"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	file := r.URL.Query().Get("file")
	if file == "" {
		file = sshconfig.DefaultPath()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"file":     config.ExpandHome(file),
		"hosts":    candidates,
		"warnings": warnings,
	})
}

func (s *server) handleSSHConfigImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		File       string   `json:"file"`
		Aliases    []string `json:"aliases"`
		PolicyMode string   `json:"policy_mode"`
		Overwrite  bool     `json:"overwrite"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.PolicyMode == "" {
		in.PolicyMode = config.ModeDeny
	}
	switch in.PolicyMode {
	case config.ModeDeny, config.ModeReadonly, config.ModeAllow:
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("policy_mode 只能是 deny、readonly 或 allow，收到 %q", in.PolicyMode))
		return
	}

	if in.File == "" {
		in.File = sshconfig.DefaultPath()
	}
	in.File = config.ExpandHome(in.File)
	res, err := sshconfig.Parse(in.File)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}

	wanted := make(map[string]bool, len(in.Aliases))
	for _, a := range in.Aliases {
		wanted[a] = true
	}
	entries := res.Hosts[:0]
	for _, e := range res.Hosts {
		if wanted[e.Alias] {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("没有选中任何主机"))
		return
	}

	converted := sshconfig.Convert(entries, sshconfig.ConvertOptions{PolicyMode: in.PolicyMode})
	cfg := s.broker().Config()
	var toWrite []config.Host
	skipped := []string{}
	warnings := []string{}
	for _, c := range converted {
		warnings = append(warnings, c.Warnings...)
		if _, err := cfg.Host(c.Host.Name); err == nil && !in.Overwrite {
			skipped = append(skipped, c.Host.Name)
			continue
		}
		toWrite = append(toWrite, c.Host)
	}
	if err := config.UpsertHosts(s.cfgPath, toWrite); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := s.reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	written := make([]string, 0, len(toWrite))
	for _, h := range toWrite {
		written = append(written, h.Name)
	}
	slog.Info("imported from ssh config", "file", in.File, "hosts", len(written), "mode", in.PolicyMode)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"imported": written,
		"skipped":  skipped,
		"warnings": warnings,
	})
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	if err := exec.Command(cmd, append(args, url)...).Start(); err != nil {
		slog.Warn("could not open a browser", "err", err, "url", url)
	}
}
