package mcpsrv

import (
	"context"
	"fmt"
	"path/filepath"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/policy"
)

// Backend is the subset of *broker.Broker the MCP tools use. It exists so a
// token-scoped view can be substituted for the full broker on the HTTP
// transport.
type Backend interface {
	Hosts(tags, patterns []string, includeDisabled bool) []broker.HostInfo
	FindHosts(q broker.HostQuery) []broker.HostInfo
	DescribeHost(name string) (broker.HostInfo, error)
	Exec(ctx context.Context, req broker.ExecRequest) (*broker.ExecResult, error)
	ExecMany(ctx context.Context, req broker.MultiExecRequest) ([]*broker.ExecResult, error)
	Upload(ctx context.Context, req broker.UploadRequest) (*broker.TransferResult, error)
	Download(ctx context.Context, req broker.DownloadRequest) (*broker.TransferResult, error)
	PolicyCheck(host, command string) (policy.Decision, error)
	AuditQuery(f audit.Filter, limit int) ([]audit.Record, error)
	AuditPath() string
}

var _ Backend = (*broker.Broker)(nil)

// scoped restricts a broker to the hosts a token may touch. An empty host and
// tag list means "all hosts".
type scoped struct {
	base  Backend
	token string
	hosts []string
	tags  []string
}

func (s *scoped) allows(name string) bool {
	if len(s.hosts) == 0 && len(s.tags) == 0 {
		return true
	}
	for _, p := range s.hosts {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	if len(s.tags) > 0 {
		info, err := s.base.DescribeHost(name)
		if err == nil {
			have := map[string]struct{}{}
			for _, t := range info.Tags {
				have[t] = struct{}{}
			}
			all := true
			for _, t := range s.tags {
				if _, ok := have[t]; !ok {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
	}
	return false
}

func (s *scoped) deniedHost(name string) error {
	return fmt.Errorf("host %q is not permitted for MCP token %q", name, s.token)
}

func (s *scoped) Hosts(tags, patterns []string, includeDisabled bool) []broker.HostInfo {
	return s.FindHosts(broker.HostQuery{Tags: tags, Names: patterns, IncludeDisabled: includeDisabled})
}

func (s *scoped) FindHosts(q broker.HostQuery) []broker.HostInfo {
	all := s.base.FindHosts(q)
	out := all[:0]
	for _, h := range all {
		if s.allows(h.Name) {
			out = append(out, h)
		}
	}
	return out
}

func (s *scoped) DescribeHost(name string) (broker.HostInfo, error) {
	if !s.allows(name) {
		return broker.HostInfo{}, s.deniedHost(name)
	}
	return s.base.DescribeHost(name)
}

func (s *scoped) Exec(ctx context.Context, req broker.ExecRequest) (*broker.ExecResult, error) {
	if !s.allows(req.Host) {
		return nil, s.deniedHost(req.Host)
	}
	return s.base.Exec(ctx, req)
}

func (s *scoped) ExecMany(ctx context.Context, req broker.MultiExecRequest) ([]*broker.ExecResult, error) {
	// Resolve the selection first, verify every host is permitted, then pass an
	// explicit name list down so the base broker cannot fan out any further.
	candidates := s.base.FindHosts(broker.HostQuery{Tags: req.Tags, Names: req.Hosts, Query: req.Query})
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no hosts matched (names=%v tags=%v)", req.Hosts, req.Tags)
	}
	names := make([]string, 0, len(candidates))
	for _, h := range candidates {
		if !s.allows(h.Name) {
			return nil, s.deniedHost(h.Name)
		}
		names = append(names, h.Name)
	}
	scopedReq := req
	scopedReq.Hosts = names
	scopedReq.Tags = nil
	return s.base.ExecMany(ctx, scopedReq)
}

func (s *scoped) Upload(ctx context.Context, req broker.UploadRequest) (*broker.TransferResult, error) {
	if !s.allows(req.Host) {
		return nil, s.deniedHost(req.Host)
	}
	return s.base.Upload(ctx, req)
}

func (s *scoped) Download(ctx context.Context, req broker.DownloadRequest) (*broker.TransferResult, error) {
	if !s.allows(req.Host) {
		return nil, s.deniedHost(req.Host)
	}
	return s.base.Download(ctx, req)
}

func (s *scoped) PolicyCheck(host, command string) (policy.Decision, error) {
	if !s.allows(host) {
		return policy.Decision{}, s.deniedHost(host)
	}
	return s.base.PolicyCheck(host, command)
}

func (s *scoped) AuditQuery(f audit.Filter, limit int) ([]audit.Record, error) {
	// A scoped token may only read audit records for hosts it can reach.
	records, err := s.base.AuditQuery(f, limit)
	if err != nil {
		return nil, err
	}
	out := records[:0]
	for _, r := range records {
		if s.allows(r.Host) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *scoped) AuditPath() string { return s.base.AuditPath() }
