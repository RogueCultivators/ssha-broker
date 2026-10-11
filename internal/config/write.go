package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// UpsertHost adds or replaces a host in the config file at path.
//
// The file is edited as a YAML node tree, so hand-written comments and keys the
// editor does not know about survive wherever the merge does not reach. The
// result is validated by a full reload before it is kept: on any error the
// previous file is restored byte for byte.
func UpsertHost(path string, h Host) error {
	return UpsertHosts(path, []Host{h})
}

// UpsertHosts adds or replaces several hosts in a single write, so an import of
// fifty machines is one backup and one atomic edit.
func UpsertHosts(path string, hosts []Host) error {
	if len(hosts) == 0 {
		return nil
	}
	doc, err := readDocument(path)
	if err != nil {
		return err
	}
	seq, err := hostsSequence(doc)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		node, err := encodeNode(h)
		if err != nil {
			return err
		}
		if existing := findHostNode(seq, h.Name); existing != nil {
			mergeNode(existing, node)
			continue
		}
		// Merging into an empty mapping is how the encoded host gets pruned of
		// empty blocks (`host_key: {}`) before it is appended.
		pruned := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		mergeNode(pruned, node)
		if len(seq.Content) > 0 {
			// Separate appended entries the way a human would.
			pruned.HeadComment = "\n"
		}
		seq.Content = append(seq.Content, pruned)
	}
	return writeDocument(path, doc)
}

// UpsertGitAccount adds or replaces one git account without touching hosts.
func UpsertGitAccount(path string, account GitAccount) error {
	doc, err := readDocument(path)
	if err != nil {
		return err
	}
	seq, err := gitAccountsSequence(doc)
	if err != nil {
		return err
	}
	node, err := encodeNode(account)
	if err != nil {
		return err
	}
	if existing := findHostNode(seq, account.Name); existing != nil {
		mergeNode(existing, node)
		return writeDocument(path, doc)
	}
	pruned := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mergeNode(pruned, node)
	if len(seq.Content) > 0 {
		pruned.HeadComment = "\n"
	}
	seq.Content = append(seq.Content, pruned)
	return writeDocument(path, doc)
}

// DeleteGitAccount removes an account by name. A missing account is an error,
// same as DeleteHost, so the editor can tell the operator the name was wrong.
func DeleteGitAccount(path, name string) error {
	doc, err := readDocument(path)
	if err != nil {
		return err
	}
	seq, err := gitAccountsSequence(doc)
	if err != nil {
		return err
	}
	for i, n := range seq.Content {
		if scalarValue(n, "name") == name {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return writeDocument(path, doc)
		}
	}
	return fmt.Errorf("git account %q not found in %s", name, path)
}

func gitAccountsSequence(doc *yaml.Node) (*yaml.Node, error) {
	root, err := rootMapping(doc)
	if err != nil {
		return nil, err
	}
	_, gitNode, ok := mapLookup(root, "git")
	if !ok {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "git"}
		gitNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, key, gitNode)
	}
	if gitNode.Kind != yaml.MappingNode {
		return nil, errors.New("config: git must be a mapping")
	}
	if _, seq, ok := mapLookup(gitNode, "accounts"); ok {
		if seq.Kind != yaml.SequenceNode {
			return nil, errors.New("config: git.accounts must be a list")
		}
		return seq, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "accounts"}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	gitNode.Content = append(gitNode.Content, key, seq)
	return seq, nil
}

// DeleteHost removes a host by name.
func DeleteHost(path, name string) error {
	doc, err := readDocument(path)
	if err != nil {
		return err
	}
	hosts, err := hostsSequence(doc)
	if err != nil {
		return err
	}
	for i, n := range hosts.Content {
		if scalarValue(n, "name") == name {
			hosts.Content = append(hosts.Content[:i], hosts.Content[i+1:]...)
			return writeDocument(path, doc)
		}
	}
	return fmt.Errorf("host %q not found in %s", name, path)
}

// ---------------------------------------------------------------------------
// node helpers
// ---------------------------------------------------------------------------

func readDocument(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{
			Kind:    yaml.DocumentNode,
			Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}},
		}
	}
	return &doc, nil
}

func rootMapping(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, errors.New("config: unexpected YAML shape")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("config: the document root must be a mapping")
	}
	return root, nil
}

// mapLookup returns the value node for key, plus its index in the alternating
// key/value slice.
func mapLookup(m *yaml.Node, key string) (int, *yaml.Node, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i, m.Content[i+1], true
		}
	}
	return 0, nil, false
}

func scalarValue(n *yaml.Node, key string) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	_, v, ok := mapLookup(n, key)
	if !ok || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

func hostsSequence(doc *yaml.Node) (*yaml.Node, error) {
	root, err := rootMapping(doc)
	if err != nil {
		return nil, err
	}
	if _, v, ok := mapLookup(root, "hosts"); ok {
		if v.Kind != yaml.SequenceNode {
			return nil, errors.New("config: hosts must be a list")
		}
		return v, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hosts"}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, key, seq)
	return seq, nil
}

func findHostNode(seq *yaml.Node, name string) *yaml.Node {
	for _, n := range seq.Content {
		if scalarValue(n, "name") == name {
			return n
		}
	}
	return nil
}

func encodeNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// isEmptyNode reports whether a node carries no data, so that writing a host
// with, say, an empty host_key block does not litter the file with `{}`.
func isEmptyNode(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.MappingNode, yaml.SequenceNode:
		return len(n.Content) == 0
	case yaml.ScalarNode:
		return n.Tag == "!!null"
	}
	return false
}

func lookupIn(m *yaml.Node, key string) (*yaml.Node, bool) {
	_, v, ok := mapLookup(m, key)
	return v, ok
}

// mergeNode makes dst carry the data of src.
//
// Mappings are merged key by key so that untouched fields keep their comments
// and their original formatting; a key that src drops or leaves empty is removed
// from dst, which is what makes "clear this field in the editor" work. Anything
// else (scalars, non-empty lists) is replaced wholesale, keeping dst's comments.
func mergeNode(dst, src *yaml.Node) {
	if dst.Kind == yaml.MappingNode && src.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(dst.Content); i += 2 {
			sv, ok := lookupIn(src, dst.Content[i].Value)
			if !ok || isEmptyNode(sv) {
				dst.Content = append(dst.Content[:i], dst.Content[i+2:]...)
				i -= 2
			}
		}
		for i := 0; i+1 < len(src.Content); i += 2 {
			sk, sv := src.Content[i], src.Content[i+1]
			if dv, ok := lookupIn(dst, sk.Value); ok {
				mergeNode(dv, sv)
				continue
			}
			if isEmptyNode(sv) {
				continue
			}
			dst.Content = append(dst.Content, sk, sv)
		}
		return
	}

	// Replace the value but keep the anchor and any comment attached to dst.
	anchor := dst.Anchor
	dst.Kind = src.Kind
	dst.Tag = src.Tag
	dst.Value = src.Value
	dst.Style = src.Style
	dst.Content = src.Content
	dst.Alias = src.Alias
	dst.Anchor = anchor
}

// blankLine matches a whitespace-only line, which the YAML emitter produces for
// blank-line comment separators.
var blankLine = regexp.MustCompile(`(?m)^[ \t]+$\n`)

// writeDocument renders doc with two-space indentation and swaps it in, after
// validating it by loading the result. On failure the original bytes return.
func writeDocument(path string, doc *yaml.Node) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	// The emitter writes an indented blank line where we asked for a separator;
	// emit a real blank line instead of leaving trailing whitespace behind.
	out := blankLine.ReplaceAll(buf.Bytes(), []byte("\n"))

	original, readErr := os.ReadFile(path)
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, out, mode); err != nil {
		return err
	}

	if _, err := Load(path); err != nil {
		if readErr == nil {
			_ = os.WriteFile(path, original, mode)
		} else {
			_ = os.Remove(path)
		}
		return fmt.Errorf("rejected: %w", err)
	}

	// Keep one backup of the last known-good file for the operator.
	if readErr == nil {
		_ = os.WriteFile(path+".bak", original, mode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// global settings
// ---------------------------------------------------------------------------

// policyKeys are the only policy keys the settings form owns. The lists
// (allow_commands, deny_commands, deny_paths, redact_patterns) are not among
// them, and that is the point: they are written by hand, often at length, and a
// form that saved the whole block would delete every one of them.
var policyKeys = []string{"mode", "disclosure", "redact_output", "timeout", "max_output_bytes"}

// auditKeys is the same idea for the audit block. `path` is not one of them:
// moving the log from a form would orphan the records already written.
var auditKeys = []string{"store_output", "max_field_bytes"}

// SetGlobals writes the global policy and the audit settings in a single edit,
// so that one save is one backup of the state before the form.
//
// A field left at its zero value is removed from the file, which is how the
// form says "inherit the built-in default" rather than pinning a value.
func SetGlobals(path string, spec Spec, auditCfg AuditConfig) error {
	doc, err := readDocument(path)
	if err != nil {
		return err
	}

	policy := map[string]any{}
	if spec.Mode != "" {
		policy["mode"] = spec.Mode
	}
	if spec.Disclosure != "" {
		policy["disclosure"] = spec.Disclosure
	}
	if spec.RedactOutput {
		policy["redact_output"] = true
	}
	if spec.Timeout > 0 {
		policy["timeout"] = spec.Timeout
	}
	if spec.MaxOutputBytes > 0 {
		policy["max_output_bytes"] = spec.MaxOutputBytes
	}
	if err := setBlock(doc, "policy", policy, policyKeys); err != nil {
		return err
	}

	audit := map[string]any{}
	if auditCfg.StoreOutput != nil {
		audit["store_output"] = *auditCfg.StoreOutput
	}
	if auditCfg.MaxFieldBytes > 0 {
		audit["max_field_bytes"] = auditCfg.MaxFieldBytes
	}
	if err := setBlock(doc, "audit", audit, auditKeys); err != nil {
		return err
	}

	return writeDocument(path, doc)
}

// setBlock applies values to one top-level mapping, touching only the named
// keys. A key that values does not carry is removed from the document; every
// other key is left exactly as it was found.
func setBlock(doc *yaml.Node, block string, values map[string]any, keys []string) error {
	src, err := encodeNode(values)
	if err != nil {
		return err
	}
	dst, err := mappingAt(doc, block)
	if err != nil {
		return err
	}
	for _, key := range keys {
		sv, ok := lookupIn(src, key)
		if !ok || isEmptyNode(sv) {
			removeKey(dst, key)
			continue
		}
		if dv, ok := lookupIn(dst, key); ok {
			mergeNode(dv, sv)
			continue
		}
		kn, err := encodeNode(key)
		if err != nil {
			return err
		}
		dst.Content = append(dst.Content, kn, sv)
	}
	return nil
}

// mappingAt returns the top-level mapping under key, creating it when the key is
// missing and replacing it when it holds something that is not a mapping.
func mappingAt(doc *yaml.Node, key string) (*yaml.Node, error) {
	root, err := rootMapping(doc)
	if err != nil {
		return nil, err
	}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	idx, v, ok := mapLookup(root, key)
	switch {
	case !ok:
		kn, err := encodeNode(key)
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, kn, m)
	case v.Kind != yaml.MappingNode:
		root.Content[idx+1] = m
	default:
		return v, nil
	}
	return m, nil
}

func removeKey(m *yaml.Node, key string) {
	idx, _, ok := mapLookup(m, key)
	if !ok {
		return
	}
	m.Content = append(m.Content[:idx], m.Content[idx+2:]...)
}
