package vmess

import (
	"context"
	"net"
	"os"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	"github.com/gofrs/uuid/v5"
	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ adapter.NodeServer = (*Server)(nil)

type Server struct {
	logger         logger.ContextLogger
	router         boxAdapter.ConnectionRouterEx
	listener       *inbound.Listener
	serviceOptions []vmess.ServiceOption
	// service is replaced, never updated, when users change: its
	// UpdateUsers is not safe while connections authenticate.
	service   atomic.Pointer[vmess.Service[int]]
	tlsConfig tls.ServerConfig
	transport boxAdapter.V2RayServerTransport
}

func New(options inbound.NodeOptions) (*Server, error) {
	server := &Server{logger: options.Logger}
	var err error
	server.router, err = options.StreamRouter()
	if err != nil {
		return nil, err
	}
	if timeFunc := ntp.TimeFuncFromContext(options.Context); timeFunc != nil {
		server.serviceOptions = append(server.serviceOptions, vmess.ServiceWithTimeFunc(timeFunc))
	}
	if options.Config.Transport != nil {
		server.serviceOptions = append(server.serviceOptions, vmess.ServiceWithDisableHeaderProtection())
	}
	err = server.UpdateUsers(nil)
	if err != nil {
		return nil, err
	}
	if options.Config.TLS != nil {
		server.tlsConfig, err = options.NewTLSServer()
		if err != nil {
			return nil, err
		}
	}
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
	return E.Errors(s.listener.CloseStream(s.transport), common.Close(s.service.Load(), s.tlsConfig))
}

func (s *Server) UpdateUsers(users []adapter.User) error {
	var (
		ids   []int
		uuids []string
	)
	for _, user := range users {
		// One malformed UUID would make the service reject the whole list.
		if _, err := uuid.FromString(user.UUID); err != nil {
			s.logger.Warn("skip user ", user.ID, ": invalid uuid")
			continue
		}
		ids = append(ids, user.ID)
		uuids = append(uuids, user.UUID)
	}
	service := vmess.NewService[int](boxAdapter.NewUpstreamContextHandler(s.newConnectionEx, s.newPacketConnectionEx), s.serviceOptions...)
	err := service.UpdateUsers(ids, uuids, make([]int, len(ids)))
	if err != nil {
		return err
	}
	err = service.Start()
	if err != nil {
		return err
	}
	if previous := s.service.Swap(service); previous != nil {
		// Only stops the legacy alter ID refresh; handshakes in flight keep working.
		previous.Close()
	}
	return nil
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
	metadata.Inbound = C.TypeVMess
	metadata.InboundType = C.TypeVMess
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
	metadata.Inbound = C.TypeVMess
	metadata.InboundType = C.TypeVMess
	ctx = inbound.UserContext(ctx, &metadata, userID)
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		s.logger.DebugContext(ctx, "[", userID, "] inbound packet addr connection")
	} else {
		s.logger.DebugContext(ctx, "[", userID, "] inbound packet connection to ", metadata.Destination)
	}
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
