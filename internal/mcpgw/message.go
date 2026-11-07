// Package mcpgw implements the AgentBox MCP gateway: a policy-enforcing reverse
// proxy for MCP over Streamable HTTP.
//
// Agents are configured with http://<gateway>/mcp/<server> and never see the
// real MCP server, its address or its credentials. The gateway
//
//   - decides every tools/call against policy before anything is forwarded,
//   - filters tools/list responses so denied tools are not even advertised,
//   - blocks methods outside an allow-list, JSON-RPC batches, and
//     server-initiated requests (sampling, elicitation, roots),
//   - mints its own session IDs so clients cannot pivot between upstreams, and
//   - fails closed on any parse error or controller failure.
package mcpgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	errBatch      = errors.New("batch requests are not supported")
	errNotObject  = errors.New("message must be a JSON object")
	errAmbiguous  = errors.New("ambiguous JSON message")
	errBadMessage = errors.New("invalid JSON-RPC message")
)

const (
	maxJSONDepth = 64
	maxMethodLen = 128
	maxToolLen   = 256
)

// Keys of a JSON-RPC message and of tools/call params. Go's encoding/json
// matches struct fields case-insensitively and accepts duplicate keys, while
// other parsers may not, so a hostile client could present one interpretation
// to the gateway and another to the MCP server. To rule this out the gateway
// rejects duplicate keys and case-variants of these keys anywhere in a message
// and decodes into case-sensitive maps.
var (
	messageKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}
	callKeys    = []string{"name", "arguments", "_meta"}
)

// message is a decoded JSON-RPC message with exact, case-sensitive key access.
type message struct {
	fields map[string]json.RawMessage
	ID     json.RawMessage // nil when absent or null
	Method string
	Params json.RawMessage
}

func (m *message) hasID() bool { return len(m.ID) > 0 }
func (m *message) isResponse() bool {
	_, r := m.fields["result"]
	_, e := m.fields["error"]
	return m.Method == "" && (r || e)
}
func (m *message) isRequest() bool      { return m.Method != "" && m.hasID() }
func (m *message) isNotification() bool { return m.Method != "" && !m.hasID() }

// parseMessage strictly decodes a single JSON-RPC message.
func parseMessage(body []byte) (*message, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty body", errBadMessage)
	}
	switch trimmed[0] {
	case '[':
		return nil, errBatch
	case '{':
	default:
		return nil, errNotObject
	}
	if err := checkDuplicateKeys(trimmed); err != nil {
		return nil, err
	}
	fields, err := decodeObject(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadMessage, err)
	}
	if err := checkKeyCase(fields, messageKeys); err != nil {
		return nil, err
	}
	m := &message{fields: fields}

	if v, ok := fields["jsonrpc"]; !ok || string(bytes.TrimSpace(v)) != `"2.0"` {
		return nil, fmt.Errorf("%w: jsonrpc must be \"2.0\"", errBadMessage)
	}
	if raw, ok := fields["id"]; ok {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || (raw[0] != '"' && raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') && string(raw) != "null") {
			return nil, fmt.Errorf("%w: id must be a string or number", errBadMessage)
		}
		if string(raw) != "null" {
			m.ID = raw
		}
	}
	if raw, ok := fields["method"]; ok {
		if err := json.Unmarshal(raw, &m.Method); err != nil || m.Method == "" || len(m.Method) > maxMethodLen {
			return nil, fmt.Errorf("%w: invalid method", errBadMessage)
		}
	}
	m.Params = fields["params"]
	if m.Method == "" && !m.isResponse() {
		return nil, fmt.Errorf("%w: neither a request, notification nor response", errBadMessage)
	}
	return m, nil
}

func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// checkKeyCase rejects keys that equal a known key only case-insensitively.
func checkKeyCase(fields map[string]json.RawMessage, known []string) error {
	for k := range fields {
		for _, want := range known {
			if k != want && strings.EqualFold(k, want) {
				return fmt.Errorf("%w: key %q", errAmbiguous, k)
			}
		}
	}
	return nil
}

// callParams extracts the tool name from tools/call params.
func callParams(params json.RawMessage) (name string, err error) {
	if len(params) == 0 {
		return "", fmt.Errorf("%w: missing params", errBadMessage)
	}
	fields, err := decodeObject(params)
	if err != nil {
		return "", fmt.Errorf("%w: params must be an object", errBadMessage)
	}
	if err := checkKeyCase(fields, callKeys); err != nil {
		return "", err
	}
	raw, ok := fields["name"]
	if !ok {
		return "", fmt.Errorf("%w: missing tool name", errBadMessage)
	}
	if err := json.Unmarshal(raw, &name); err != nil || name == "" || len(name) > maxToolLen {
		return "", fmt.Errorf("%w: invalid tool name", errBadMessage)
	}
	return name, nil
}

// checkDuplicateKeys walks the whole document and fails on any object that
// repeats a key, on excessive nesting, and on trailing data.
func checkDuplicateKeys(b []byte) error {
	type frame struct {
		isObj     bool
		expectKey bool
		keys      map[string]struct{}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var stack []frame
	completed := 0

	valueDone := func() {
		if len(stack) == 0 {
			completed++
			return
		}
		if top := &stack[len(stack)-1]; top.isObj {
			top.expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", errBadMessage, err)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("%w: nesting too deep", errBadMessage)
				}
				stack = append(stack, frame{isObj: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("%w: nesting too deep", errBadMessage)
				}
				stack = append(stack, frame{})
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
				valueDone()
			}
		default:
			if len(stack) > 0 {
				if top := &stack[len(stack)-1]; top.isObj && top.expectKey {
					key, _ := t.(string)
					if _, dup := top.keys[key]; dup {
						return fmt.Errorf("%w: duplicate key %q", errAmbiguous, key)
					}
					top.keys[key] = struct{}{}
					top.expectKey = false
					continue
				}
			}
			valueDone()
		}
	}
	if completed != 1 {
		return fmt.Errorf("%w: trailing data", errBadMessage)
	}
	return nil
}

// rpcError builds a JSON-RPC error response. id may be nil (null).
func rpcError(id json.RawMessage, code int, message string, data map[string]any) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	return b
}

// JSON-RPC error codes used by the gateway (implementation-defined range).
const (
	codeParse         = -32700
	codeInvalidReq    = -32600
	codeMethodBlocked = -32001
	codePolicyDenied  = -32001
	codeNoSession     = -32002
	codeUpstream      = -32003
)
