package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"ssha/internal/config"
)

// gitView is an account plus whether its sealed secret is present. The secret
// itself is never returned.
type gitView struct {
	config.GitAccount
	PasswordReady    bool `json:"password_ready"`
	PasswordSealed   bool `json:"password_sealed"`
	PassphraseReady  bool `json:"passphrase_ready"`
	PassphraseSealed bool `json:"passphrase_sealed"`
}

func gitViews(cfg *config.Config) []gitView {
	out := make([]gitView, 0, len(cfg.Git.Accounts))
	for i := range cfg.Git.Accounts {
		a := cfg.Git.Accounts[i]
		out = append(out, gitView{
			GitAccount:       a,
			PasswordReady:    config.HasSecret(a.Auth.PasswordFile),
			PasswordSealed:   config.SecretSealed(a.Auth.PasswordFile),
			PassphraseReady:  config.HasSecret(a.Auth.PassphraseFile),
			PassphraseSealed: config.SecretSealed(a.Auth.PassphraseFile),
		})
	}
	return out
}

func (s *Server) handleGit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 POST"))
		return
	}
	var in struct {
		config.GitAccount
		Password        string `json:"password"`
		Passphrase      string `json:"passphrase"`
		ClearPassword   bool   `json:"clear_password"`
		ClearPassphrase bool   `json:"clear_passphrase"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求格式不对：%w", err))
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("名称不能为空"))
		return
	}
	if in.Password != "" && in.ClearPassword {
		writeErr(w, http.StatusBadRequest, errors.New("不能同时填写和清除密码"))
		return
	}
	if in.Passphrase != "" && in.ClearPassphrase {
		writeErr(w, http.StatusBadRequest, errors.New("不能同时填写和清除口令"))
		return
	}

	account := in.GitAccount
	account.Name = in.Name
	// A typed secret must not be written into the config. The file path is
	// filled in below, after the value has been sealed. Check the account
	// first so a rejected form does not leave an orphaned secret file.
	account.Auth.PasswordFile = strings.TrimSpace(account.Auth.PasswordFile)
	account.Auth.PassphraseFile = strings.TrimSpace(account.Auth.PassphraseFile)
	if account.Auth.Type == "https" {
		account.Auth.KeyPath = ""
		account.Auth.KeyEnv = ""
		account.Auth.PassphraseEnv = ""
		account.Auth.PassphraseFile = ""
	} else if account.Auth.Type == "ssh" {
		account.Auth.Username = ""
		account.Auth.PasswordEnv = ""
		account.Auth.PasswordFile = ""
	}
	if err := account.Normalize(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}

	if in.Password != "" {
		path, err := config.WriteGitSecret(s.cfgPath, account.Name, config.SecretPassword, in.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("保存密码失败：%w", err))
			return
		}
		account.Auth.PasswordEnv = ""
		account.Auth.PasswordFile = path
	}
	if in.Passphrase != "" {
		path, err := config.WriteGitSecret(s.cfgPath, account.Name, config.SecretPassphrase, in.Passphrase)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("保存口令失败：%w", err))
			return
		}
		account.Auth.PassphraseEnv = ""
		account.Auth.PassphraseFile = path
	}
	if in.ClearPassword {
		account.Auth.PasswordFile = ""
	}
	if in.ClearPassphrase {
		account.Auth.PassphraseFile = ""
	}

	if err := config.UpsertGitAccount(s.cfgPath, account); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	if in.ClearPassword {
		if err := config.DeleteGitSecret(s.cfgPath, account.Name, config.SecretPassword); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("删除密码失败：%w", err))
			return
		}
	}
	if in.ClearPassphrase {
		if err := config.DeleteGitSecret(s.cfgPath, account.Name, config.SecretPassphrase); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("删除口令失败：%w", err))
			return
		}
	}
	if err := s.reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": account.Name})
}

func (s *Server) handleGitAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/git/")
	if name == "" || strings.Contains(name, "/") {
		writeErr(w, http.StatusBadRequest, errors.New("需要账号名称"))
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		writeErr(w, http.StatusMethodNotAllowed, errors.New("请用 DELETE"))
		return
	}
	if err := config.DeleteGitAccount(s.cfgPath, name); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	_ = config.DeleteGitSecret(s.cfgPath, name, config.SecretPassword)
	_ = config.DeleteGitSecret(s.cfgPath, name, config.SecretPassphrase)
	if err := s.reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
