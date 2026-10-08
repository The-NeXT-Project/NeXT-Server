package tuic

import (
	"context"
	"net"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	"github.com/gofrs/uuid/v5"
	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.NodeServer = (*Server)(nil)

type Server struct {
	logger    logger.ContextLogger
	router    boxAdapter.ConnectionRouterEx
	listener  *inbound.Listener
	tlsConfig tls.ServerConfig
	service   *tuic.Service[int]
}

func New(options inbound.NodeOptions) (*Server, error) {
	if options.Config.TLS == nil {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(options.Context, options.Logger, *options.Config.TLS)
	if err != nil {
		return nil, err
	}
	tlsConfig = inbound.OptionalALPN(tlsConfig)
	server := &Server{
		logger:    options.Logger,
		router:    uot.NewRouter(options.Router, options.Logger),
		tlsConfig: tlsConfig,
	}
	udpTimeout := time.Duration(options.Server.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = C.UDPTimeout
	}
	server.service, err = tuic.NewService[int](tuic.ServiceOptions{
		Context:           options.Context,
		Logger:            options.Logger,
		TLSConfig:         tlsConfig,
		QUICOptions:       qtls.QUICOptions{},
		CongestionControl: options.Config.TUIC.CongestionControl,
		// Panel profiles turn 0-RTT on for clients.
		ZeroRTTHandshake: true,
		UDPTimeout:       udpTimeout,
		Handler:          server,
	})
	if err != nil {
		return nil, err
	}
	server.listener, err = options.NewListener(nil, nil, true)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Start() error {
	err := s.tlsConfig.Start()
	if err != nil {
		return err
	}
	packetConn, err := s.listener.ListenUDP()
	if err != nil {
		return err
	}
	return s.service.Start(packetConn)
}

func (s *Server) Close() error {
	return common.Close(s.listener, s.tlsConfig, s.service)
}

// UpdateUsers authenticates users by UUID and password.
func (s *Server) UpdateUsers(users []adapter.User) error {
	var (
		ids       []int
		uuids     [][16]byte
		passwords []string
	)
	for _, user := range users {
		userUUID, err := uuid.FromString(user.UUID)
		if err != nil {
			s.logger.Warn("skip user ", user.ID, ": invalid uuid")
			continue
		}
		ids = append(ids, user.ID)
		uuids = append(uuids, userUUID)
		passwords = append(passwords, user.Password)
	}
	s.service.UpdateUsers(ids, uuids, passwords)
	return nil
}

func (s *Server) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx, metadata, userID := s.newMetadata(ctx, source, destination)
	s.logger.DebugContext(ctx, "[", userID, "] inbound connection to ", metadata.Destination)
	s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *Server) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx, metadata, userID := s.newMetadata(ctx, source, destination)
	s.logger.DebugContext(ctx, "[", userID, "] inbound packet connection to ", metadata.Destination)
	s.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *Server) newMetadata(ctx context.Context, source M.Socksaddr, destination M.Socksaddr) (context.Context, boxAdapter.InboundContext, int) {
	var metadata boxAdapter.InboundContext
	metadata.Inbound = C.TypeTUIC
	metadata.InboundType = C.TypeTUIC
	metadata.OriginDestination = s.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	userID, _ := auth.UserFromContext[int](ctx)
	ctx = inbound.UserContext(log.ContextWithNewID(ctx), &metadata, userID)
	return ctx, metadata, userID
}
