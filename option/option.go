package option

import (
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type Options struct {
	Log *boxOption.LogOptions `json:"log,omitempty"`
	// Sentry needs a build with -tags with_sentry.
	Sentry *SentryOptions `json:"sentry,omitempty"`
	// Pprof needs a build with -tags with_pprof.
	Pprof   *PprofOptions   `json:"pprof,omitempty"`
	Servers []ServerOptions `json:"servers"`
}

type SentryOptions struct {
	// DSN falls back to the SENTRY_DSN environment variable.
	DSN         string `json:"dsn,omitempty"`
	Environment string `json:"environment,omitempty"`
	// CrashFile receives the report of a crash that cannot be recovered,
	// such as a panic in a connection, and is sent on the next start.
	CrashFile string `json:"crash_file,omitempty"`
}

type PprofOptions struct {
	// Listen serves net/http/pprof, e.g. "127.0.0.1:6060". It has no
	// authentication; keep it on loopback.
	Listen string `json:"listen,omitempty"`
	// CPUProfile records a CPU profile from start to shutdown, usable as
	// default.pgo for profile-guided optimization.
	CPUProfile string `json:"cpu_profile,omitempty"`
}

const APITypeServerV1 = "server_v1"

type ServerOptions struct {
	// API selects the panel protocol. Only "server_v1" (NeXT-Panel Server API V1,
	// the default) is implemented.
	API     string             `json:"api,omitempty"`
	URL     string             `json:"url"`
	Key     string             `json:"key"`
	Timeout badoption.Duration `json:"timeout,omitempty"`

	PullInterval badoption.Duration `json:"pull_interval,omitempty"`
	PushInterval badoption.Duration `json:"push_interval,omitempty"`

	// The listen port always comes from the panel.
	boxOption.ListenOptions

	// ProxyProtocol accepts a PROXY protocol v1/v2 header on TCP connections.
	// Without ProxyProtocolTrusted any client may send one and set its own
	// source address, so only enable it behind a relay or a firewall.
	ProxyProtocol        bool     `json:"proxy_protocol,omitempty"`
	ProxyProtocolTrusted []string `json:"proxy_protocol_trusted,omitempty"`

	// TLS is the certificate source for TLS node types: certificate_path and
	// key_path, or acme. The panel's host fills in server_name and an empty
	// acme domain. Without a certificate a self-signed one is generated, which
	// clients only accept with allow_insecure.
	TLS       *boxOption.InboundTLSOptions       `json:"tls,omitempty"`
	Multiplex *boxOption.InboundMultiplexOptions `json:"multiplex,omitempty"`

	Dialer     *boxOption.DialerOptions `json:"dialer,omitempty"`
	FrontProxy *FrontProxyOptions       `json:"front_proxy,omitempty"`
}
