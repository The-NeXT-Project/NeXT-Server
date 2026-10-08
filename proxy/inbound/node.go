package inbound

import (
	"context"
	"net/netip"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

// NodeOptions is what every node server is built from.
type NodeOptions struct {
	Context context.Context
	Logger  logger.ContextLogger
	Router  adapter.Router
	Config  *adapter.NodeConfig
	Server  option.ServerOptions
}

// NewListener binds to the panel's port with the local listen options.
func (o NodeOptions) NewListener(network []string, packetHandler boxAdapter.PacketHandler, udpFragment bool) (*Listener, error) {
	listenOptions := o.Server.ListenOptions
	listenOptions.ListenPort = o.Config.ListenPort
	if listenOptions.Listen == nil {
		// sing-box would bind to loopback.
		listenOptions.Listen = common.Ptr(badoption.Addr(netip.IPv6Unspecified()))
	}
	listenOptions.UDPFragmentDefault = udpFragment
	return New(Options{
		Context:              o.Context,
		Logger:               o.Logger,
		Listen:               listenOptions,
		Network:              network,
		PacketHandler:        packetHandler,
		ProxyProtocol:        o.Server.ProxyProtocol,
		ProxyProtocolTrusted: o.Server.ProxyProtocolTrusted,
	})
}

// StreamRouter wraps the router with UoT and, unless disabled locally,
// sing-mux, the way sing-box's TCP inbounds do.
func (o NodeOptions) StreamRouter() (boxAdapter.ConnectionRouterEx, error) {
	router := boxAdapter.ConnectionRouterEx(uot.NewRouter(o.Router, o.Logger))
	multiplex := boxOption.InboundMultiplexOptions{Enabled: true}
	if o.Server.Multiplex != nil {
		multiplex = *o.Server.Multiplex
	}
	return mux.NewRouterWithOptions(router, o.Logger, multiplex)
}

// UserContext tags ctx with the panel user ID for the router and returns the
// metadata user name sing-box components log with.
func UserContext(ctx context.Context, metadata *boxAdapter.InboundContext, userID int) context.Context {
	metadata.User = F.ToString(userID)
	return auth.ContextWithUser(ctx, userID)
}
