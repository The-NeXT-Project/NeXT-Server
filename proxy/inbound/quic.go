//go:build with_quic

package inbound

// Registers the V2Ray QUIC transport, which sing-box otherwise only does
// from its include package.
import _ "github.com/sagernet/sing-box/transport/v2rayquic"
