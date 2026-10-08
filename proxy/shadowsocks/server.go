package shadowsocks

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ adapter.NodeServer = (*Server)(nil)

// Server is a multi-user Shadowsocks 2022 server on TCP and UDP.
type Server struct {
	ctx      context.Context
	logger   logger.ContextLogger
	router   boxAdapter.ConnectionRouterEx
	listener *inbound.Listener
	service  *shadowaead_2022.MultiService[int]
	keyLen   int
}

func New(options inbound.NodeOptions) (*Server, error) {
	method := options.Config.Shadowsocks.Method
	if !common.Contains(shadowaead_2022.List, method) {
		return nil, E.New("unsupported shadowsocks 2022 method: ", method)
	}
	server := &Server{
		ctx:    options.Context,
		logger: options.Logger,
		keyLen: 32,
	}
	if method == "2022-blake3-aes-128-gcm" {
		server.keyLen = 16
	}
	var err error
	server.router, err = options.StreamRouter()
	if err != nil {
		return nil, err
	}
	udpTimeout := time.Duration(options.Server.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = C.UDPTimeout
	}
	server.service, err = shadowaead_2022.NewMultiServiceWithPassword[int](
		method,
		options.Config.Shadowsocks.ServerKey,
		int64(udpTimeout.Seconds()),
		boxAdapter.NewLegacyUpstreamHandler(boxAdapter.InboundContext{}, server.newConnection, server.newPacketConnection, server),
		ntp.TimeFuncFromContext(options.Context),
	)
	if err != nil {
		return nil, E.Cause(err, "shadowsocks 2022 server key")
	}
	server.listener, err = options.NewListener([]string{N.NetworkUDP}, server, false)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Start() error {
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	s.listener.ServeTCP(tcpListener, s.handleConnection)
	return s.listener.Start()
}

func (s *Server) Close() error {
	return s.listener.Close()
}

// UpdateUsers authenticates users by password, which the panel has already
// turned into a base64 user key for the node's method.
func (s *Server) UpdateUsers(users []adapter.User) error {
	var (
		ids  []int
		keys []string
	)
	for _, user := range users {
		key, err := base64.StdEncoding.DecodeString(user.Password)
		if err != nil || len(key) != s.keyLen {
			// One bad key would make the service reject the whole list.
			s.logger.Warn("skip user ", user.ID, ": invalid shadowsocks 2022 key")
			continue
		}
		ids = append(ids, user.ID)
		keys = append(keys, user.Password)
	}
	return s.service.UpdateUsersWithPasswords(ids, keys)
}

//nolint:staticcheck
func (s *Server) handleConnection(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext) {
	err := s.service.NewConnection(ctx, conn, boxAdapter.UpstreamMetadata(metadata))
	N.CloseOnHandshakeFailure(conn, nil, err)
	if err != nil {
		s.logger.DebugContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

//nolint:staticcheck
func (s *Server) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	err := s.service.NewPacket(s.ctx, &stubPacketConn{s.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		s.logger.Debug(E.Cause(err, "process packet from ", source))
	}
}

func (s *Server) newConnection(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext) error {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	metadata.Inbound = C.TypeShadowsocks
	metadata.InboundType = C.TypeShadowsocks
	ctx = inbound.UserContext(ctx, &metadata, userID)
	s.logger.DebugContext(ctx, "[", userID, "] inbound connection to ", metadata.Destination)
	//nolint:staticcheck
	return s.router.RouteConnection(ctx, conn, metadata)
}

func (s *Server) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata boxAdapter.InboundContext) error {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	metadata.Inbound = C.TypeShadowsocks
	metadata.InboundType = C.TypeShadowsocks
	ctx = inbound.UserContext(log.ContextWithNewID(ctx), &metadata, userID)
	s.logger.DebugContext(ctx, "[", userID, "] inbound packet connection to ", metadata.Destination)
	//nolint:staticcheck
	return s.router.RoutePacketConnection(ctx, conn, metadata)
}

func (s *Server) NewError(ctx context.Context, err error) {
	if E.IsClosedOrCanceled(err) {
		return
	}
	s.logger.DebugContext(ctx, err)
}

// stubPacketConn lets the service write replies through the listener.
type stubPacketConn struct {
	N.PacketWriter
}

func (c *stubPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	panic("stub!")
}

func (c *stubPacketConn) Close() error {
	return nil
}

func (c *stubPacketConn) LocalAddr() net.Addr {
	panic("stub!")
}

func (c *stubPacketConn) SetDeadline(t time.Time) error {
	panic("stub!")
}

func (c *stubPacketConn) SetReadDeadline(t time.Time) error {
	panic("stub!")
}

func (c *stubPacketConn) SetWriteDeadline(t time.Time) error {
	panic("stub!")
}
