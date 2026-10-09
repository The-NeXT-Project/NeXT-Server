package inbound

import (
	stdTLS "crypto/tls"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
)

// NewTLSServer is sing-box's TLS server for the node, except that with ACME a
// client asking for a name no certificate covers gets the node's own
// certificate, as with a fixed certificate. A CDN in front of the node asks
// for its own name; a strict match would refuse it, and certmagic's fallback
// name is not exposed by sing-box.
func (o NodeOptions) NewTLSServer() (tls.ServerConfig, error) {
	options := *o.Config.TLS
	config, err := tls.NewServer(o.Context, o.Logger, options)
	if err != nil || config == nil {
		return config, err
	}
	//nolint:staticcheck
	acme := options.ACME
	if acme == nil || len(acme.Domain) == 0 || (options.Reality != nil && options.Reality.Enabled) {
		return config, nil
	}
	fallback := acme.DefaultServerName
	if fallback == "" {
		fallback = acme.Domain[0]
	}
	// The config itself: sing-box hands out this one, its clones and clones
	// with other ALPN, so the hook reaches every transport.
	std, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	if std.GetCertificate != nil {
		std.GetCertificate = fallbackCertificate(std.GetCertificate, fallback)
	}
	return config, nil
}

func fallbackCertificate(getCertificate func(*stdTLS.ClientHelloInfo) (*stdTLS.Certificate, error), fallback string) func(*stdTLS.ClientHelloInfo) (*stdTLS.Certificate, error) {
	return func(hello *stdTLS.ClientHelloInfo) (*stdTLS.Certificate, error) {
		certificate, err := getCertificate(hello)
		// A TLS-ALPN challenge must only ever see its own certificate.
		if err == nil || strings.EqualFold(hello.ServerName, fallback) ||
			slices.Contains(hello.SupportedProtos, C.ACMETLS1Protocol) {
			return certificate, err
		}
		withFallback := *hello
		withFallback.ServerName = fallback
		return getCertificate(&withFallback)
	}
}
