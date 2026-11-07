// Package audit records policy decisions and other security-relevant events.
//
// Events are redacted before they are queued, written to SQLite in batches by
// a single background worker, and published to live subscribers. Prompts and
// file contents are omitted unless explicitly enabled.
package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Redacted replaces secret values in audit output.
const Redacted = "[REDACTED]"

// Omitted replaces content values that are not collected by default.
const Omitted = "[OMITTED]"

const (
	defaultMaxString = 512
	defaultMaxBytes  = 8 << 10
	regexInputCap    = 64 << 10
	maxDepth         = 6
	maxCollection    = 100
)

// Redactor scrubs secrets and (by default) content from event metadata.
// The zero value is ready to use with safe defaults.
type Redactor struct {
	// IncludeContent keeps prompt/completion/file-content style fields.
	// It must only be enabled by an explicit user opt-in.
	IncludeContent bool
	// MaxString truncates individual strings (default 512 bytes).
	MaxString int
	// MaxBytes caps the encoded metadata size (default 8 KiB).
	MaxBytes int
}

// Substrings (after lowercasing and removing '-' and '_') that mark a key as secret.
var sensitiveKeyParts = []string{
	"authorization", "cookie", "token", "secret", "password", "passwd", "passphrase",
	"apikey", "accesskey", "secretkey", "privatekey", "credential", "bearer",
	"signature", "mcpsession",
}

// Keys whose values are content, omitted unless IncludeContent is set.
var contentKeys = map[string]bool{
	"prompt": true, "completion": true, "messages": true, "content": true,
	"body": true, "requestbody": true, "responsebody": true, "filecontent": true,
	"filecontents": true, "text": true, "input": true, "output": true,
}

var exactSensitiveKeys = map[string]bool{"key": true, "auth": true, "pwd": true, "sig": true}

func normKey(k string) string {
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "-", "")
	k = strings.ReplaceAll(k, "_", "")
	return k
}

func isSensitiveKey(k string) bool {
	n := normKey(k)
	if exactSensitiveKeys[n] {
		return true
	}
	for _, p := range sensitiveKeyParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

type pattern struct {
	re   *regexp.Regexp
	repl string
}

var valuePatterns = []pattern{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), Redacted},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + Redacted},
	{regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{20,})`), Redacted},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}`), Redacted},
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`), "${1}" + Redacted + "@"},
	{regexp.MustCompile(`(?i)([?&;](?:access_token|id_token|refresh_token|token|api[_-]?key|key|secret|password|sig|signature|auth|code)=)[^&\s#]+`), "${1}" + Redacted},
	{regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*)\s*[=:]\s*['"]?[^\s'"&,;]{4,}`), "${1}=" + Redacted},
}

func (r Redactor) maxString() int {
	if r.MaxString > 0 {
		return r.MaxString
	}
	return defaultMaxString
}

func (r Redactor) maxBytes() int {
	if r.MaxBytes > 0 {
		return r.MaxBytes
	}
	return defaultMaxBytes
}

// String redacts secret-looking substrings and truncates the result.
func (r Redactor) String(s string) string {
	if len(s) > regexInputCap {
		s = truncateUTF8(s, regexInputCap)
	}
	for _, p := range valuePatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return truncateString(s, r.maxString())
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return truncateUTF8(s, n) + "…[truncated]"
}

// Metadata returns the redacted JSON encoding of m. Values are normalized via
// a JSON round trip so arbitrary Go types are handled uniformly.
func (r Redactor) Metadata(m map[string]any) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage(`{}`)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{"error":"unencodable metadata"}`)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return json.RawMessage(`{"error":"unencodable metadata"}`)
	}
	out, err := json.Marshal(r.walk(v, 0))
	if err != nil {
		return json.RawMessage(`{"error":"unencodable metadata"}`)
	}
	if len(out) > r.maxBytes() {
		b, _ := json.Marshal(map[string]any{"truncated": true, "original_bytes": len(out)})
		return b
	}
	return out
}

func (r Redactor) walk(v any, depth int) any {
	if depth > maxDepth {
		return "[TRUNCATED_DEPTH]"
	}
	switch x := v.(type) {
	case string:
		return r.String(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		n := 0
		for k, val := range x {
			if n++; n > maxCollection {
				out["_truncated"] = true
				break
			}
			switch {
			case isSensitiveKey(k):
				out[k] = Redacted
			case !r.IncludeContent && contentKeys[normKey(k)]:
				out[k] = Omitted
			default:
				out[k] = r.walk(val, depth+1)
			}
		}
		return out
	case []any:
		if len(x) > maxCollection {
			x = x[:maxCollection]
		}
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = r.walk(val, depth+1)
		}
		return out
	default:
		return v
	}
}
