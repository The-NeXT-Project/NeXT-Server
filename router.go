package nextserver

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Router = (*Server)(nil)

// RouteConnectionEx is where every proxied TCP connection lands once a node
// server has authenticated it.
func (s *Server) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	onClose = onceClose(onClose)
	user, err := s.connectionUser(ctx)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if s.auditor.enabled() {
		conn, err = s.auditStream(ctx, conn, &metadata, user)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			s.logger.InfoContext(ctx, "[", user.id, "] ", err)
			return
		}
	}
	err = s.resolve(ctx, &metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, err)
		return
	}
	done := user.open(metadata.Source.Addr)
	if limiter := user.limiter.Load(); limiter != nil {
		conn = limiter.Conn(user.ctx, conn)
	}
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&user.upload}, []*atomic.Int64{&user.download})
	stop := context.AfterFunc(user.ctx, func() { conn.Close() })
	s.connections.NewConnection(ctx, s.dialer, conn, metadata, func(err error) {
		stop()
		done()
		onClose(err)
	})
}

func (s *Server) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc) {
	onClose = onceClose(onClose)
	user, err := s.connectionUser(ctx)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if s.auditor.enabled() {
		conn, err = s.auditPacket(ctx, conn, &metadata, user)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			if !E.IsClosedOrCanceled(err) {
				s.logger.InfoContext(ctx, "[", user.id, "] ", err)
			}
			return
		}
	}
	err = s.resolve(ctx, &metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, err)
		return
	}
	done := user.open(metadata.Source.Addr)
	if limiter := user.limiter.Load(); limiter != nil {
		conn = limiter.PacketConn(user.ctx, conn)
	}
	conn = bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&user.upload}, nil, []*atomic.Int64{&user.download}, nil)
	stop := context.AfterFunc(user.ctx, func() { conn.Close() })
	s.connections.NewPacketConnection(ctx, s.dialer, conn, metadata, func(err error) {
		stop()
		done()
		onClose(err)
	})
}

// RouteConnection serves handlers that still use the blocking interface,
// such as Shadowsocks and UoT. It returns once the connection is done.
func (s *Server) RouteConnection(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext) error {
	done := make(chan error, 1)
	s.RouteConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

func (s *Server) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata boxAdapter.InboundContext) error {
	done := make(chan error, 1)
	s.RoutePacketConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

// onceClose makes onClose safe to call more than once, and to call at all:
// node servers pass nil for connections nobody waits on.
func onceClose(onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	if onClose == nil {
		return func(error) {}
	}
	return N.OnceClose(onClose)
}

func (s *Server) connectionUser(ctx context.Context) (*userState, error) {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return nil, E.New("connection without user")
	}
	user := s.users.get(userID)
	if user == nil {
		// Removed between authentication and routing.
		return nil, E.New("user ", userID, " is no longer served")
	}
	return user, nil
}

var streamSniffers = []sniff.StreamSniffer{
	sniff.TLSClientHello,
	sniff.HTTPHost,
	sniff.StreamDomainNameQuery,
	sniff.BitTorrent,
	sniff.SSH,
	sniff.RDP,
}

var packetSniffers = []sniff.PacketSniffer{
	sniff.QUICClientHello,
	sniff.DomainNameQuery,
	sniff.STUNMessage,
	sniff.UTP,
	sniff.UDPTracker,
	sniff.DTLSRecord,
}

// auditStream peeks at the first payload and refuses the connection when a
// detect rule matches.
func (s *Server) auditStream(ctx context.Context, conn net.Conn, metadata *boxAdapter.InboundContext, user *userState) (net.Conn, error) {
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	buffer := buf.NewPacket()
	// A server-first protocol sends nothing until the timeout; that is fine.
	_ = sniff.PeekStream(ctx, metadata, conn, nil, buffer, 0, streamSniffers...)
	rule, hit := s.auditor.match(destinationHost(metadata.Destination), metadata.Domain, buffer.Bytes())
	if buffer.IsEmpty() {
		buffer.Release()
	} else {
		conn = bufio.NewCachedConn(conn, buffer)
	}
	if hit {
		s.auditor.record(user.id, rule.ID)
		return conn, E.New("blocked by detect rule ", rule.ID, ": ", metadata.Destination)
	}
	return conn, nil
}

func (s *Server) auditPacket(ctx context.Context, conn N.PacketConn, metadata *boxAdapter.InboundContext, user *userState) (N.PacketConn, error) {
	buffer := buf.NewPacket()
	destination, err := conn.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return conn, err
	}
	if !metadata.Destination.IsValid() || metadata.Destination.Addr.IsUnspecified() {
		metadata.Destination = destination
	}
	_ = sniff.PeekPacket(ctx, metadata, buffer.Bytes(), packetSniffers...)
	rule, hit := s.auditor.match(destinationHost(destination), metadata.Domain, buffer.Bytes())
	conn = bufio.NewCachedPacketConn(conn, buffer, destination)
	if hit {
		s.auditor.record(user.id, rule.ID)
		return conn, E.New("blocked by detect rule ", rule.ID, ": ", destination)
	}
	return conn, nil
}

func destinationHost(destination M.Socksaddr) string {
	if destination.IsFqdn() {
		return destination.Fqdn
	}
	if destination.Addr.IsValid() {
		return destination.Addr.String()
	}
	return ""
}

// resolve looks up a domain destination, unless a front proxy should get it
// unresolved. sing-box's dialer only accepts addresses.
func (s *Server) resolve(ctx context.Context, metadata *boxAdapter.InboundContext) error {
	if !s.resolveDomain || !metadata.Destination.IsFqdn() || len(metadata.DestinationAddresses) > 0 {
		return nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", metadata.Destination.Fqdn)
	if err != nil {
		return E.Cause(err, "lookup ", metadata.Destination.Fqdn)
	}
	metadata.DestinationAddresses = common.Map(addresses, netip.Addr.Unmap)
	return nil
}
