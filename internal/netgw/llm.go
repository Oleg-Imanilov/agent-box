package netgw

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/Oleg-Imanilov/agent-box/internal/secretfile"
)

// Provider describes an LLM upstream served at /llm/<Name>/.
//
// The agent's LLM base URL points at the gateway over plain HTTP on the
// isolated network. The gateway forwards to Upstream (normally HTTPS) and sets
// the real credential, so the agent only ever holds a dummy key. This is the
// only way to inject credentials without intercepting TLS.
type Provider struct {
	// Name is the route name: lowercase letters, digits and dashes.
	Name string `json:"name"`
	// Upstream is the base URL, e.g. https://api.openai.com or http://ollama.internal:11434.
	Upstream string `json:"upstream"`
	// Header is the header carrying the credential (default "Authorization").
	Header string `json:"header,omitempty"`
	// Scheme is prepended to the key, e.g. "Bearer" (default for Authorization).
	Scheme string `json:"scheme,omitempty"`
	// KeyFile is read on use (so keys can be rotated); NoAuth disables injection.
	KeyFile string `json:"key_file,omitempty"`
	NoAuth  bool   `json:"no_auth,omitempty"`
	// Extra static headers to set on every upstream request (e.g. anthropic-version).
	Headers map[string]string `json:"headers,omitempty"`
}

var providerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Headers an agent may send that must never reach the upstream, because the
// gateway owns authentication.
var credentialHeaders = []string{"Authorization", "X-Api-Key", "Api-Key", "Cookie", "X-Goog-Api-Key", "Proxy-Authorization"}

const maxLLMRequestBytes = 64 << 20

type provider struct {
	Provider
	target *url.URL
	keys   *secretfile.File
}

func buildProviders(list []Provider) (map[string]*provider, error) {
	out := map[string]*provider{}
	for _, p := range list {
		if !providerNameRe.MatchString(p.Name) {
			return nil, fmt.Errorf("provider %q: invalid name", p.Name)
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("provider %q: duplicate", p.Name)
		}
		u, err := url.Parse(p.Upstream)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("provider %q: upstream must be an http(s) URL without credentials, query or fragment", p.Name)
		}
		if !p.NoAuth && p.KeyFile == "" {
			return nil, fmt.Errorf("provider %q: key_file is required unless no_auth is set", p.Name)
		}
		if p.NoAuth && p.KeyFile != "" {
			return nil, fmt.Errorf("provider %q: key_file and no_auth are mutually exclusive", p.Name)
		}
		if p.Header == "" {
			p.Header = "Authorization"
			if p.Scheme == "" {
				p.Scheme = "Bearer"
			}
		}
		if strings.ContainsAny(p.Header, " :\r\n") || strings.ContainsAny(p.Scheme, "\r\n") {
			return nil, fmt.Errorf("provider %q: invalid header or scheme", p.Name)
		}
		for k, v := range p.Headers {
			if strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(v, "\r\n") {
				return nil, fmt.Errorf("provider %q: invalid static header %q", p.Name, k)
			}
		}
		pr := &provider{Provider: p, target: u}
		if p.KeyFile != "" {
			pr.keys = secretfile.New(p.KeyFile)
		}
		out[p.Name] = pr
	}
	return out, nil
}

func (g *Gateway) handleLLM(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/llm/")
	name, _, _ := strings.Cut(rest, "/")
	p, ok := g.providers[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !g.acquire() {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer g.release()

	var key string
	if !p.NoAuth {
		var err error
		if key, err = p.keys.Get(); err != nil {
			g.log.Error("provider key unavailable", "provider", p.Name, "err", err)
			http.Error(w, "provider credentials unavailable", http.StatusBadGateway)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLLMRequestBytes)
	g.llmProxy(p, key).ServeHTTP(w, r)
}

func (g *Gateway) llmProxy(p *provider, key string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			in := pr.In
			rest := strings.TrimPrefix(in.URL.Path, "/llm/"+p.Name)
			out := *p.target
			out.Path = strings.TrimSuffix(p.target.Path, "/") + rest
			out.RawPath = ""
			out.RawQuery = in.URL.RawQuery
			pr.Out.URL = &out
			pr.Out.Host = out.Host

			for _, h := range credentialHeaders {
				pr.Out.Header.Del(h)
			}
			for k, v := range p.Headers {
				pr.Out.Header.Set(k, v)
			}
			if !p.NoAuth {
				v := key
				if p.Scheme != "" {
					v = p.Scheme + " " + key
				}
				pr.Out.Header.Set(p.Header, v)
			}
		},
		Transport:     g.transport(),
		FlushInterval: -1, // stream SSE completions without buffering
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeDeniedOrError(w, err)
		},
	}
}
