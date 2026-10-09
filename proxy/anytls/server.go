package anytls

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
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
	padding   []byte
	// service is replaced, never updated, when users change: its
	// UpdateUsers is not safe while connections authenticate.
	service atomic.Pointer[anytls.Service]
}

func New(options inbound.NodeOptions) (*Server, error) {
	server := &Server{
		logger: options.Logger,
		// AnyTLS multiplexes by itself, so only UDP over TCP is unwrapped.
		router: uot.NewRouter(options.Router, options.Logger),
	}
	var err error
	if options.Config.TLS != nil {
		server.tlsConfig, err = options.NewTLSServer()
		if err != nil {
			return nil, err
		}
	}
	server.padding = padding.DefaultPaddingScheme
	if len(options.Config.AnyTLS.PaddingScheme) > 0 {
		server.padding = []byte(strings.Join(options.Config.AnyTLS.PaddingScheme, "\n"))
	}
	err = server.UpdateUsers(nil)
	if err != nil {
		return nil, err
	}
	server.listener, err = options.NewListener(nil, nil, false)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Start() error {
	return inbound.StartStream(s.listener, s.logger, s.tlsConfig, nil, s.newConnection)
}

func (s *Server) Close() error {
	return common.Close(s.listener, s.tlsConfig)
}

// UpdateUsers authenticates users by password. The service reports users by
// name, so the name is the panel user ID.
func (s *Server) UpdateUsers(users []adapter.User) error {
	anyTLSUsers := make([]anytls.User, 0, len(users))
	for _, user := range users {
		if user.Password == "" {
			continue
		}
		anyTLSUsers = append(anyTLSUsers, anytls.User{Name: strconv.Itoa(user.ID), Password: user.Password})
	}
	service, err := anytls.NewService(anytls.ServiceConfig{
		Users:         anyTLSUsers,
		PaddingScheme: s.padding,
		Handler:       (*serviceHandler)(s),
		Logger:        s.logger,
	})
	if err != nil {
		return err
	}
	s.service.Store(service)
	return nil
}

func (s *Server) newConnection(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := s.service.Load().NewConnection(boxAdapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

type serviceHandler Server

func (s *serviceHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	userName, _ := auth.UserFromContext[string](ctx)
	userID, err := strconv.Atoi(userName)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	var metadata boxAdapter.InboundContext
	metadata.Inbound = C.TypeAnyTLS
	metadata.InboundType = C.TypeAnyTLS
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	ctx = inbound.UserContext(ctx, &metadata, userID)
	s.logger.DebugContext(ctx, "[", userID, "] inbound connection to ", metadata.Destination)
	s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
