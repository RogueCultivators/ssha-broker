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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/config"
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

	token, err := newToken()
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
	mux.Handle("/api/test", s.auth(http.HandlerFunc(s.handleTest)))
	mux.Handle("/api/hostkey", s.auth(http.HandlerFunc(s.handleHostKey)))
	mux.Handle("/api/audit", s.auth(http.HandlerFunc(s.handleAudit)))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	url := "http://" + addr + "/?token=" + token
	fmt.Fprintf(os.Stderr, "ssha ui\n  config: %s\n  open:   %s\n\n", s.cfgPath, url)
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
		return fmt.Errorf("refusing to serve the editor on %s: it would let anything on the network rewrite the ssha config; use 127.0.0.1 or tunnel it", addr)
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
}

type statePayload struct {
	ConfigPath string      `json:"config_path"`
	AuditPath  string      `json:"audit_path"`
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
		Version:    s.version,
		Global:     cfg.GlobalPolicy(),
		Defaults:   cfg.Defaults,
	}
	for i := range cfg.Hosts {
		h := cfg.Hosts[i]
		spec := cfg.EffectivePolicy(&h)
		out.Hosts = append(out.Hosts, hostView{
			Host:          h,
			Effective:     spec,
			EffectiveMode: spec.Mode,
			Warnings:      hostWarnings(&h, spec),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// hostWarnings flags the mistakes that silently make a host useless: no host
// key pinned, no password source, a jump host that is itself unreachable.
func hostWarnings(h *config.Host, spec config.Spec) []string {
	var out []string
	if h.Auth.Type == "password" && h.Auth.PasswordEnv == "" && h.Auth.PasswordFile == "" {
		out = append(out, "no password source: the CLI will prompt interactively, but an agent over MCP will fail. Set password_env or password_file.")
	}
	if h.Auth.Type == "key" && h.Auth.KeyPath == "" && h.Auth.KeyEnv == "" {
		out = append(out, "auth.type is key but no key_path or key_env is set.")
	}
	if len(h.HostKey.Fingerprints) == 0 && h.HostKey.KnownHosts == "" && !h.HostKey.Insecure {
		out = append(out, "no host key pinned: known_hosts defaults to ~/.ssh/known_hosts; if the host is not in it, the connection is refused (use host-key scan).")
	}
	if h.HostKey.Insecure {
		out = append(out, "host_key.insecure is on: the server identity is not verified.")
	}
	if spec.Mode == config.ModeReadonly && len(spec.Allow) == 0 {
		out = append(out, "policy mode readonly with an empty allow list would block everything.")
	}
	if spec.RedactOutput && spec.Disclosure == config.DisclosureFull {
		out = append(out, "redact_output hides the address in output, but disclosure full still shows the address in ssh_list_hosts.")
	}
	return out
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("use POST"))
		return
	}
	var h config.Host
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&h); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid host payload: %w", err))
		return
	}
	if h.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("name is required"))
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
		writeErr(w, http.StatusBadRequest, errors.New("host name is required"))
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
		writeErr(w, http.StatusMethodNotAllowed, errors.New("use DELETE"))
	}
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
		writeErr(w, http.StatusBadRequest, errors.New("addr is required"))
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
