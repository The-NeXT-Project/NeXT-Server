package trojan

import (
	"context"
	"net"
	"os"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.NodeServer = (*Server)(nil)

type Server struct {
	logger   logger.ContextLogger
	router   boxAdapter.ConnectionRouterEx
	listener *inbound.Listener
	// service is replaced, never updated, when users change: its
	// UpdateUsers is not safe while connections authenticate.
	service   atomic.Pointer[trojan.Service[int]]
	tlsConfig tls.ServerConfig
	transport boxAdapter.V2RayServerTransport
}

func New(options inbound.NodeOptions) (*Server, error) {
	if options.Config.TLS == nil {
		return nil, C.ErrTLSRequired
	}
	server := &Server{logger: options.Logger}
	var err error
	server.router, err = options.StreamRouter()
	if err != nil {
		return nil, err
	}
	server.tlsConfig, err = options.NewTLSServer()
	if err != nil {
		return nil, err
	}
	server.service.Store(server.newService())
	if options.Config.Transport != nil {
		server.transport, err = v2ray.NewServerTransport(options.Context, options.Logger, *options.Config.Transport, server.tlsConfig, (*transportHandler)(server))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Config.Transport.Type)
		}
	}
	server.listener, err = options.NewListener(nil, nil, false)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Start() error {
	return inbound.StartStream(s.listener, s.logger, s.tlsConfig, s.transport, s.newConnection)
}

func (s *Server) Close() error {
	return E.Errors(s.listener.CloseStream(s.transport), common.Close(s.tlsConfig))
}

// UpdateUsers authenticates users by UUID, which the panel hands to Trojan
// clients as their password.
func (s *Server) UpdateUsers(users []adapter.User) error {
	var (
		ids       []int
		passwords []string
	)
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		if user.UUID == "" {
			continue
		}
		// A repeated password would make the service reject the whole list.
		if seen[user.UUID] {
			s.logger.Warn("skip user ", user.ID, ": uuid shared with another user")
			continue
		}
		seen[user.UUID] = true
		ids = append(ids, user.ID)
		passwords = append(passwords, user.UUID)
	}
	service := s.newService()
	err := service.UpdateUsers(ids, passwords)
	if err != nil {
		return err
	}
	s.service.Store(service)
	return nil
}

func (s *Server) newService() *trojan.Service[int] {
	return trojan.NewService[int](boxAdapter.NewUpstreamContextHandler(s.newConnectionEx, s.newPacketConnectionEx), nil, s.logger)
}

func (s *Server) newConnection(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := s.service.Load().NewConnection(boxAdapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (s *Server) newConnectionEx(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	metadata.Inbound = C.TypeTrojan
	metadata.InboundType = C.TypeTrojan
	ctx = inbound.UserContext(ctx, &metadata, userID)
	s.logger.DebugContext(ctx, "[", userID, "] inbound connection to ", metadata.Destination)
	s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *Server) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	metadata.Inbound = C.TypeTrojan
	metadata.InboundType = C.TypeTrojan
	ctx = inbound.UserContext(ctx, &metadata, userID)
	s.logger.DebugContext(ctx, "[", userID, "] inbound packet connection to ", metadata.Destination)
	s.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

type transportHandler Server

func (s *transportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata boxAdapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	s.logger.DebugContext(ctx, "inbound connection from ", metadata.Source)
	(*Server)(s).newConnection(ctx, conn, metadata, onClose)
}
