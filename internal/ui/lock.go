package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"ssha/internal/config"
)

const (
	sessionIdle                = 30 * time.Minute
	minAdminRunes              = 8
	maxAdminBytes              = 1024
	uiAuthVersion              = 1
	argonKeyLen                = 32
	defaultArgonTime    uint32 = 3
	defaultArgonMemory  uint32 = 64 * 1024
	defaultArgonThreads uint8  = 4
)

// kdfParams is the Argon2id cost used when setting a new management password.
// A zero Time means the production cost. Tests set a cheaper cost on the server.
type kdfParams struct {
	time    uint32
	memory  uint32
	threads uint8
}

func (p kdfParams) orDefault() kdfParams {
	if p.time == 0 {
		return kdfParams{time: defaultArgonTime, memory: defaultArgonMemory, threads: defaultArgonThreads}
	}
	return p
}

// uiAuth is the management password verifier. The password itself is never stored.
type uiAuth struct {
	Version int    `json:"version"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
}

type loginGuard struct {
	fails int
	until time.Time
}

func uiAuthPath(configPath string) string {
	return filepath.Join(config.SecretsDir(configPath), "ui-auth.json")
}

func (s *Server) loadAdmin() (uiAuth, bool, error) {
	b, err := os.ReadFile(uiAuthPath(s.cfgPath))
	if err != nil {
		if os.IsNotExist(err) {
			return uiAuth{}, false, nil
		}
		return uiAuth{}, false, err
	}
	var a uiAuth
	if err := json.Unmarshal(b, &a); err != nil {
		return uiAuth{}, false, errors.New("管理密码文件损坏")
	}
	if a.Version != uiAuthVersion || a.Hash == "" || a.Salt == "" || a.Time == 0 || a.Memory == 0 || a.Threads == 0 {
		return uiAuth{}, false, errors.New("管理密码文件损坏")
	}
	return a, true, nil
}

func writeAdmin(configPath string, a uiAuth) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := config.SecretsDir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := uiAuthPath(configPath)
	tmp, err := os.CreateTemp(dir, ".ui-auth-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (a uiAuth) matches(password string) bool {
	salt, err := base64.StdEncoding.DecodeString(a.Salt)
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(a.Hash)
	if err != nil || len(want) == 0 {
		return false
	}
	sum := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(sum, want) == 1
}

func newAdmin(password string, cost kdfParams) (uiAuth, error) {
	cost = cost.orDefault()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return uiAuth{}, err
	}
	sum := argon2.IDKey([]byte(password), salt, cost.time, cost.memory, cost.threads, argonKeyLen)
	return uiAuth{
		Version: uiAuthVersion,
		Time:    cost.time,
		Memory:  cost.memory,
		Threads: cost.threads,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Hash:    base64.StdEncoding.EncodeToString(sum),
	}, nil
}

func normalizeAdminPassword(password, confirm string) (string, error) {
	password = strings.TrimSpace(password)
	confirm = strings.TrimSpace(confirm)
	if password != confirm {
		return "", errors.New("两次输入不一致")
	}
	if utf8.RuneCountInString(password) < minAdminRunes {
		return "", errors.New("管理密码至少 8 位")
	}
	if len(password) > maxAdminBytes {
		return "", errors.New("管理密码太长")
	}
	return password, nil
}

func (s *Server) issueSession() (string, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.issueSessionLocked()
}

func (s *Server) issueSessionLocked() (string, error) {
	id, err := newToken()
	if err != nil {
		return "", err
	}
	if s.sessions == nil {
		s.sessions = map[string]time.Time{}
	}
	s.sessions[id] = time.Now().Add(sessionIdle)
	return id, nil
}

func (s *Server) rotateSessions() (string, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.sessions = map[string]time.Time{}
	return s.issueSessionLocked()
}

func (s *Server) clearSessions() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.sessions = map[string]time.Time{}
}

func (s *Server) validSession(id string) bool {
	if id == "" {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	exp, ok := s.sessions[id]
	if !ok || !time.Now().Before(exp) {
		delete(s.sessions, id)
		return false
	}
	s.sessions[id] = time.Now().Add(sessionIdle)
	return true
}

func (s *Server) beginLogin() error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.guard.until.After(time.Now()) {
		return errors.New("试太多次了，请稍后再试")
	}
	return nil
}

func (s *Server) failLogin() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.guard.fails++
	if s.guard.fails < 5 {
		return
	}
	shift := s.guard.fails - 4
	if shift > 5 {
		shift = 5
	}
	s.guard.until = time.Now().Add(time.Second * time.Duration(1<<shift))
}

func (s *Server) resetLogin() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.guard = loginGuard{}
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The session is issued only after the password checks out, and it lives
		// in this process. Deleting the password file takes effect on the next
		// start, which is also when the operator is told to reopen the window.
		if !s.validSession(r.Header.Get("X-SSHA-Session")) {
			_, configured, err := s.loadAdmin()
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":      "需要管理密码",
				"locked":     true,
				"configured": configured,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.sessionStatus(w, r)
	case http.MethodPost:
		s.sessionLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 GET 或 POST"))
	}
}

func (s *Server) sessionStatus(w http.ResponseWriter, r *http.Request) {
	_, ok, err := s.loadAdmin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": ok,
		"unlocked":   ok && s.validSession(r.Header.Get("X-SSHA-Session")),
	})
}

func (s *Server) sessionLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求格式不对：%w", err))
		return
	}
	auth, configured, err := s.loadAdmin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !configured {
		s.sessionSetup(w, in.Password, in.Confirm)
		return
	}
	if err := s.beginLogin(); err != nil {
		writeErr(w, http.StatusTooManyRequests, err)
		return
	}
	if !auth.matches(strings.TrimSpace(in.Password)) {
		s.failLogin()
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "管理密码不对",
			"code":  "password",
		})
		return
	}
	s.resetLogin()
	id, err := s.issueSession()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session": id, "configured": true})
}

func (s *Server) sessionSetup(w http.ResponseWriter, password, confirm string) {
	password, err := normalizeAdminPassword(password, confirm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, ok, err := s.loadAdmin(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	} else if ok {
		writeErr(w, http.StatusConflict, errors.New("已经设置过管理密码"))
		return
	}
	auth, err := newAdmin(password, s.kdf)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Hashing is slow. Check again so a second first-run that finished first
	// is not overwritten. The rename still makes the file itself atomic.
	if _, ok, err := s.loadAdmin(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	} else if ok {
		writeErr(w, http.StatusConflict, errors.New("已经设置过管理密码"))
		return
	}
	if err := writeAdmin(s.cfgPath, auth); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("保存管理密码失败：%w", err))
		return
	}
	s.resetLogin()
	id, err := s.issueSession()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session": id, "configured": true})
}

func (s *Server) handleSessionLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 POST"))
		return
	}
	s.clearSessions()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSessionPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 POST"))
		return
	}
	var in struct {
		Old      string `json:"old"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求格式不对：%w", err))
		return
	}
	auth, ok, err := s.loadAdmin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, errors.New("还没有设置管理密码"))
		return
	}
	if err := s.beginLogin(); err != nil {
		writeErr(w, http.StatusTooManyRequests, err)
		return
	}
	if !auth.matches(strings.TrimSpace(in.Old)) {
		s.failLogin()
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "当前密码不对",
			"code":  "password",
		})
		return
	}
	password, err := normalizeAdminPassword(in.Password, in.Confirm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	next, err := newAdmin(password, s.kdf)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := writeAdmin(s.cfgPath, next); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("保存管理密码失败：%w", err))
		return
	}
	s.resetLogin()
	id, err := s.rotateSessions()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session": id})
}
