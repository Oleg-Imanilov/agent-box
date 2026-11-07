// Package policy defines the AgentBox policy format and the engine that
// evaluates network and MCP decisions.
//
// Rules are scoped (global, agent, session). Evaluation is default-deny and
// deny always takes precedence over allow across all scopes.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

	"gopkg.in/yaml.v3"
)

const (
	// MaxPolicyBytes bounds the size of a policy document accepted by Parse.
	MaxPolicyBytes = 256 << 10
	maxListEntries = 1000
	maxMCPServers  = 200

	ModeReadWrite = "read-write"
	ModeReadOnly  = "read-only"
)

var (
	serverNameRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	toolPatternRe = regexp.MustCompile(`^[A-Za-z0-9_.:/*-]{1,256}$`)
)

// Policy is the declarative policy document. YAML and JSON are both accepted
// (JSON is a subset of YAML); the stored/canonical form is JSON.
type Policy struct {
	Agent     string               `yaml:"agent,omitempty" json:"agent,omitempty"`
	Workspace *Workspace           `yaml:"workspace,omitempty" json:"workspace,omitempty"`
	Network   Network              `yaml:"network,omitempty" json:"network,omitzero"`
	MCP       map[string]MCPServer `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	Audit     Audit                `yaml:"audit,omitempty" json:"audit,omitzero"`
}

// Workspace describes the host directory made available to the agent. It is
// consumed by the launcher; the engine does not evaluate it.
type Workspace struct {
	Path string `yaml:"path" json:"path"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// Network holds destination rules in the form host:port.
//
// host is an exact domain, a "*.suffix" wildcard (subdomains only), an IP
// address, or a CIDR; IPv6 hosts must be bracketed. port is N, A-B, or *.
type Network struct {
	Default string   `yaml:"default,omitempty" json:"default,omitempty"`
	Allow   []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny    []string `yaml:"deny,omitempty" json:"deny,omitempty"`
}

// MCPServer holds tool rules for one MCP server. Tool patterns are exact
// names or globs using "*". A server with no allow_tools allows nothing.
type MCPServer struct {
	AllowTools []string `yaml:"allow_tools,omitempty" json:"allow_tools,omitempty"`
	DenyTools  []string `yaml:"deny_tools,omitempty" json:"deny_tools,omitempty"`
}

// Audit holds audit options. Nil values mean the safe default (true).
type Audit struct {
	Enabled       *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	RedactSecrets *bool `yaml:"redact_secrets,omitempty" json:"redact_secrets,omitempty"`
}

// RedactSecretsEnabled reports the effective redact_secrets setting (default true).
func (a Audit) RedactSecretsEnabled() bool { return a.RedactSecrets == nil || *a.RedactSecrets }

// AuditEnabled reports the effective audit.enabled setting (default true).
func (a Audit) AuditEnabled() bool { return a.Enabled == nil || *a.Enabled }

// Parse decodes and validates a policy from YAML or JSON. Unknown fields,
// multiple documents and oversized input are rejected.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy too large (%d bytes, max %d)", len(data), MaxPolicyBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return &Policy{}, nil
		}
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse policy: multiple documents are not allowed")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the policy for structural and syntactic errors.
func (p *Policy) Validate() error {
	if p.Agent != "" && !agentNameRe.MatchString(p.Agent) {
		return fmt.Errorf("agent: invalid name %q", p.Agent)
	}
	if w := p.Workspace; w != nil {
		if w.Path == "" {
			return errors.New("workspace.path is required")
		}
		if w.Mode != "" && w.Mode != ModeReadWrite && w.Mode != ModeReadOnly {
			return fmt.Errorf("workspace.mode: must be %q or %q", ModeReadWrite, ModeReadOnly)
		}
	}
	if d := p.Network.Default; d != "" && d != "deny" {
		return errors.New(`network.default: only "deny" is supported (default-allow is not permitted)`)
	}
	if err := validateDestList("network.allow", p.Network.Allow); err != nil {
		return err
	}
	if err := validateDestList("network.deny", p.Network.Deny); err != nil {
		return err
	}
	if len(p.MCP) > maxMCPServers {
		return fmt.Errorf("mcp: too many servers (max %d)", maxMCPServers)
	}
	for name, srv := range p.MCP {
		if !serverNameRe.MatchString(name) {
			return fmt.Errorf("mcp: invalid server name %q", name)
		}
		if err := validateToolList("mcp."+name+".allow_tools", srv.AllowTools); err != nil {
			return err
		}
		if err := validateToolList("mcp."+name+".deny_tools", srv.DenyTools); err != nil {
			return err
		}
	}
	return nil
}

func validateDestList(field string, list []string) error {
	if len(list) > maxListEntries {
		return fmt.Errorf("%s: too many entries (max %d)", field, maxListEntries)
	}
	for i, s := range list {
		if _, err := parseDestRule(s); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

func validateToolList(field string, list []string) error {
	if len(list) > maxListEntries {
		return fmt.Errorf("%s: too many entries (max %d)", field, maxListEntries)
	}
	for i, s := range list {
		if !toolPatternRe.MatchString(s) {
			return fmt.Errorf("%s[%d]: invalid tool pattern %q", field, i, s)
		}
	}
	return nil
}
