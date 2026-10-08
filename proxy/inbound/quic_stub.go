//go:build !with_quic

package inbound

import (
	"context"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Without it the V2Ray QUIC transport fails with a bare "invalid argument".
func init() {
	v2ray.RegisterQUICConstructor(
		func(ctx context.Context, logger logger.ContextLogger, options boxOption.V2RayQUICOptions, tlsConfig tls.ServerConfig, handler boxAdapter.V2RayServerTransportHandler) (boxAdapter.V2RayServerTransport, error) {
			return nil, C.ErrQUICNotIncluded
		},
		func(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options boxOption.V2RayQUICOptions, tlsConfig tls.Config) (boxAdapter.V2RayClientTransport, error) {
			return nil, C.ErrQUICNotIncluded
		},
	)
}
