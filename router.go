package nextserver

import (
	"context"
	"errors"
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
	err = s.abuse.admit(ctx, user, N.NetworkTCP, metadata.Destination)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logRefusal(ctx, user, err)
		return
	}
	if s.auditor.enabled() || s.abuse.inspectsPayload() {
		conn, err = s.inspectStream(ctx, conn, &metadata, user)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			s.logRefusal(ctx, user, err)
			return
		}
	}
	err = s.resolve(ctx, &metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, err)
		return
	}
	err = s.checkDestination(&metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, "[", user.id, "] ", err)
		return
	}
	done := user.open(metadata.Source.Addr)
	if limiter := user.limiter.Load(); limiter != nil {
		conn = limiter.Conn(user.ctx, conn)
	}
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&user.upload}, []*atomic.Int64{&user.download})
	stop := context.AfterFunc(user.connectionContext(), func() { conn.Close() })
	dialer := s.dialer
	var watch *dialWatch
	if s.abuse.watchesDials() {
		watch = s.abuse.watchDial(s.dialer)
		dialer = watch
	}
	destination := metadata.Destination
	s.connections.NewConnection(ctx, dialer, conn, metadata, func(err error) {
		if watch != nil && err != nil && !watch.connected.Load() {
			s.abuse.dialFailed(ctx, user, watch, destination, err)
		}
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
	err = s.abuse.admit(ctx, user, N.NetworkUDP, metadata.Destination)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logRefusal(ctx, user, err)
		return
	}
	if s.auditor.enabled() || s.abuse.inspectsPayload() {
		conn, err = s.inspectPacket(ctx, conn, &metadata, user)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			if !E.IsClosedOrCanceled(err) {
				s.logRefusal(ctx, user, err)
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
	err = s.checkDestination(&metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		s.logger.DebugContext(ctx, "[", user.id, "] ", err)
		return
	}
	done := user.open(metadata.Source.Addr)
	// Innermost, so that dropped packets use up neither the speed limit nor
	// the user's traffic.
	conn = s.abuse.filterPackets(ctx, user, conn)
	if limiter := user.limiter.Load(); limiter != nil {
		conn = limiter.PacketConn(user.ctx, conn)
	}
	conn = bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&user.upload}, nil, []*atomic.Int64{&user.download}, nil)
	stop := context.AfterFunc(user.connectionContext(), func() { conn.Close() })
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

// logRefusal logs a refused connection. Detect rule hits are logged each
// time, as before; the abuse guard logs its own refusals, rate limited, so
// here they only go to debug.
func (s *Server) logRefusal(ctx context.Context, user *userState, err error) {
	if errors.As(err, new(abuseRefusal)) {
		s.logger.DebugContext(ctx, "[", user.id, "] ", err)
	} else {
		s.logger.InfoContext(ctx, "[", user.id, "] ", err)
	}
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

// inspectStream peeks at the first payload and refuses the connection when a
// detect rule matches or the abuse guard finds BitTorrent.
func (s *Server) inspectStream(ctx context.Context, conn net.Conn, metadata *boxAdapter.InboundContext, user *userState) (net.Conn, error) {
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	buffer := buf.NewPacket()
	// A server-first protocol sends nothing until the timeout; that is fine.
	_ = sniff.PeekStream(ctx, metadata, conn, nil, buffer, 0, streamSniffers...)
	rule, hit := s.auditor.match(destinationHost(metadata.Destination), metadata.Domain, buffer.Bytes())
	var err error
	if hit {
		s.auditor.record(user.id, rule.ID)
		err = E.New("blocked by detect rule ", rule.ID, ": ", metadata.Destination)
	} else {
		err = s.abuse.checkStream(ctx, user, metadata, buffer.Bytes())
	}
	if buffer.IsEmpty() {
		buffer.Release()
	} else {
		conn = bufio.NewCachedConn(conn, buffer)
	}
	return conn, err
}

func (s *Server) inspectPacket(ctx context.Context, conn N.PacketConn, metadata *boxAdapter.InboundContext, user *userState) (N.PacketConn, error) {
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
	if hit {
		s.auditor.record(user.id, rule.ID)
		err = E.New("blocked by detect rule ", rule.ID, ": ", destination)
	} else {
		err = s.abuse.checkPacket(ctx, user, metadata, buffer.Bytes())
	}
	conn = bufio.NewCachedPacketConn(conn, buffer, destination)
	return conn, err
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
