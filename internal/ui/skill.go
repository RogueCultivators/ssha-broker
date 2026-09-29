package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ssha/internal/config"
	"ssha/skills"
)

// A skill is a directory with a SKILL.md in it. pi and Claude Code both read the
// Agent Skills locations, and each also has one of its own, so the editor offers
// all of them rather than making the operator remember which.
type skillTarget struct {
	Label    string `json:"label"`
	Dir      string `json:"dir"`
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	UpToDate bool   `json:"up_to_date"`
}

type mcpSnippet struct {
	Label  string `json:"label"`
	Format string `json:"format"`
	Text   string `json:"text"`
}

func skillTargets() []skillTarget {
	home, _ := os.UserHomeDir()
	project := ""
	if wd, err := os.Getwd(); err == nil {
		project = filepath.Join(wd, ".agents", "skills")
	}
	candidates := []struct{ label, dir string }{
		{"pi / Claude Code（通用位置）", filepath.Join(home, ".agents", "skills")},
		{"pi 自己的位置", filepath.Join(home, ".pi", "agent", "skills")},
		{"Claude Code 自己的位置", filepath.Join(home, ".claude", "skills")},
		{"仅当前项目", project},
	}
	out := make([]skillTarget, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if c.dir == "" || seen[c.dir] {
			continue
		}
		// A systemd user service runs with the home directory as its cwd, so the
		// project entry would be the same directory as the first one.
		seen[c.dir] = true
		path := filepath.Join(c.dir, skills.Name, "SKILL.md")
		t := skillTarget{Label: c.label, Dir: c.dir, Path: path}
		if b, err := os.ReadFile(path); err == nil {
			t.Exists = true
			t.UpToDate = string(b) == skills.Content
		}
		out = append(out, t)
	}
	return out
}

// executablePath is what an MCP client should run. The absolute path is used
// rather than "ssha" because a client started from a desktop session may have a
// different PATH than the shell the operator installed from.
func executablePath() string {
	if p, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return p
	}
	return "ssha"
}

func (s *Server) mcpSnippets() []mcpSnippet {
	bin := executablePath()
	// Structs, not maps: a map marshals its keys alphabetically, and a snippet
	// people copy should read the way the documentation writes it.
	type server struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	type stdioConfig struct {
		McpServers map[string]server `json:"mcpServers"`
	}
	pretty, _ := json.MarshalIndent(stdioConfig{
		McpServers: map[string]server{"ssha": {Command: bin, Args: []string{"mcp"}}},
	}, "", "  ")
	out := []mcpSnippet{
		{
			Label:  "Claude Code / Cursor（.mcp.json、~/.cursor/mcp.json）",
			Format: "json",
			Text:   string(pretty),
		},
		{
			Label:  "Codex（~/.codex/config.toml）",
			Format: "toml",
			Text:   fmt.Sprintf("[mcp_servers.ssha]\ncommand = %q\nargs = [\"mcp\"]\n", bin),
		},
	}

	cfg := s.broker().Config()
	if len(cfg.Server.Tokens) > 0 {
		addr := cfg.Server.HTTPAddr
		if addr == "" {
			addr = "127.0.0.1:8765"
		}
		type httpServer struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		}
		type httpConfig struct {
			McpServers map[string]httpServer `json:"mcpServers"`
		}
		prettyHTTP, _ := json.MarshalIndent(httpConfig{
			McpServers: map[string]httpServer{
				"ssha": {
					URL:     fmt.Sprintf("http://%s/mcp", addr),
					Headers: map[string]string{"Authorization": "Bearer <token>"},
				},
			},
		}, "", "  ")
		out = append(out, mcpSnippet{
			Label:  "同一台机器上的 agent，走 HTTP（需要 server.tokens）",
			Format: "json",
			Text:   string(prettyHTTP),
		})
	}
	return out
}

// handleSkill reports what the skill is, where it can go, and how an agent
// connects. The skill text is not a secret: it ships in the binary and in the
// repository.
func (s *Server) handleSkill(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    skills.Name,
		"content": skills.Content,
		"targets": skillTargets(),
		"cli":     "ssha skill install",
		"mcp":     s.mcpSnippets(),
	})
}

// handleSkillDownload serves the raw markdown so the operator can copy it to a
// machine that does not have ssha installed.
func (s *Server) handleSkillDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="SKILL.md"`)
	_, _ = w.Write([]byte(skills.Content))
}

// handleSkillInstall writes the skill to <dir>/<name>/SKILL.md.
//
// The editor only ever writes this one file and one directory deep, so a dir of
// "..", a relative path or a path that is not a directory is refused rather than
// followed.
func (s *Server) handleSkillInstall(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求格式不对：%w", err))
		return
	}
	dir := config.ExpandHome(strings.TrimSpace(in.Dir))
	if dir == "" {
		writeErr(w, http.StatusBadRequest, errors.New("需要指定目录"))
		return
	}
	if !filepath.IsAbs(dir) {
		writeErr(w, http.StatusBadRequest, errors.New("目录必须是绝对路径"))
		return
	}
	// Check for a ".." component rather than for the substring: filepath.Clean
	// resolves it away, so `strings.Contains(clean, "..")` would never fire.
	for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
		if part == ".." {
			writeErr(w, http.StatusBadRequest, errors.New("目录里不能有 .."))
			return
		}
	}

	path := filepath.Join(filepath.Clean(dir), skills.Name, "SKILL.md")
	previous, readErr := os.ReadFile(path)
	existed := readErr == nil
	updated := existed && string(previous) != skills.Content

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("创建目录失败：%w", err))
		return
	}
	if err := os.WriteFile(path, []byte(skills.Content), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("写入失败：%w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"path":       path,
		"existed":    existed,
		"updated":    updated,
		"up_to_date": !updated,
	})
}
