package broker

import (
	"context"

	"ssha/internal/audit"
	"ssha/internal/config"
	"ssha/internal/gitx"
)

// GitAccounts is the agent-facing list. It does not include key paths or
// passwords.
func (b *Broker) GitAccounts() []config.GitPublic {
	out := make([]config.GitPublic, 0, len(b.cfg.Git.Accounts))
	for i := range b.cfg.Git.Accounts {
		out = append(out, b.cfg.Git.Accounts[i].Public())
	}
	return out
}

// Git runs one authenticated git operation and audits it, including denials.
func (b *Broker) Git(ctx context.Context, req gitx.Request) (*gitx.Result, error) {
	if req.Prompt == nil && b.prompt != nil {
		prompt := b.prompt
		req.Prompt = func(account, what string) (string, error) {
			return prompt(account, what)
		}
	}
	res, err := (&gitx.Runner{Config: b.cfg}).Run(ctx, req)
	if res == nil {
		return nil, err
	}
	host := res.Account
	if host == "" {
		host = res.Host
	}
	rec := &audit.Record{
		Type:       audit.TypeGit,
		Host:       host,
		Command:    res.Command,
		Path:       res.URL,
		Cwd:        req.Dir,
		Decision:   res.Decision,
		Reason:     res.Reason,
		ExitCode:   res.ExitCode,
		DurationMS: res.DurationMS,
		Truncated:  res.Truncated,
	}
	if b.storeOutput {
		rec.Stdout = truncate(res.Stdout, b.maxFieldBytes)
		rec.Stderr = truncate(res.Stderr, b.maxFieldBytes)
	}
	rec.ID = b.record(rec)
	res.AuditID = rec.ID
	if res.Decision == audit.DecisionDenied {
		return res, &DeniedError{Host: host, Command: res.Command, Reason: res.Reason}
	}
	return res, err
}
