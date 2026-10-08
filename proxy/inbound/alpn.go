package inbound

import (
	stdTLS "crypto/tls"

	"github.com/sagernet/sing-box/common/tls"
)

// OptionalALPN lets clients that offer no ALPN complete a QUIC handshake with
// a server that advertises one. QUIC servers must otherwise refuse them (RFC
// 9001, section 8.1), and clients that do offer one must refuse a server that
// selects none, so neither a fixed list nor an empty one serves both. The
// panel's sing-box profiles set no ALPN while mihomo offers h3.
func OptionalALPN(config tls.ServerConfig) tls.ServerConfig {
	return &optionalALPNConfig{config}
}

type optionalALPNConfig struct {
	tls.ServerConfig
}

func (c *optionalALPNConfig) STDConfig() (*tls.STDConfig, error) {
	config, err := c.ServerConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	config = config.Clone()
	// sing-box serves its current config, reloaded certificates included,
	// through this hook.
	current := config.GetConfigForClient
	config.GetConfigForClient = func(hello *stdTLS.ClientHelloInfo) (*stdTLS.Config, error) {
		base := config
		if current != nil {
			selected, err := current(hello)
			if err != nil {
				return nil, err
			}
			if selected != nil {
				base = selected
			}
		}
		if len(hello.SupportedProtos) > 0 || len(base.NextProtos) == 0 {
			return base, nil
		}
		withoutALPN := base.Clone()
		withoutALPN.NextProtos = nil
		return withoutALPN, nil
	}
	return config, nil
}
