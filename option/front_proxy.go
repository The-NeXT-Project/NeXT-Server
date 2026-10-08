package option

const (
	FrontProxyTypeSOCKS5  = "socks5"
	FrontProxyTypeSOCKS4  = "socks4"
	FrontProxyTypeSOCKS4A = "socks4a"
	FrontProxyTypeHTTP    = "http"
)

// FrontProxyOptions sends all outbound traffic through an upstream proxy.
type FrontProxyOptions struct {
	Type     string `json:"type"`
	Server   string `json:"server"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// ResolveDomain resolves domains locally instead of sending them to the proxy.
	ResolveDomain bool `json:"resolve_domain,omitempty"`
}
