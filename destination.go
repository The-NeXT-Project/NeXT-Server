package nextserver

import (
	"context"
	"net"
	"net/netip"
	"strings"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Networks a user must not reach beyond those netip.Addr classifies.
var privatePrefixes = []netip.Prefix{
	// "This network": Linux connects 0.0.0.0/8 to the node itself.
	netip.MustParsePrefix("0.0.0.0/8"),
	// Carrier-grade NAT, which Tailscale uses too.
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// privateAddress reports whether addr is the node itself or a network only
// the node can reach: loopback, private and link-local networks (a cloud's
// metadata service among them), multicast and broadcast.
func privateAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range privatePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// checkDestination keeps users off the node and its networks, unless
// allow_private_destinations is set. A domain keeps its public addresses.
func (s *Server) checkDestination(metadata *boxAdapter.InboundContext) error {
	if s.options.AllowPrivateDestinations {
		return nil
	}
	if metadata.Destination.IsIP() && privateAddress(metadata.Destination.Addr) {
		return E.New("private destination refused: ", metadata.Destination)
	}
	if len(metadata.DestinationAddresses) > 0 {
		public := common.Filter(metadata.DestinationAddresses, func(addr netip.Addr) bool { return !privateAddress(addr) })
		if len(public) == 0 {
			return E.New("private destination refused: ", metadata.Destination, " resolves to [",
				strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ","), "]")
		}
		metadata.DestinationAddresses = public
	}
	return nil
}

// privateFilterDialer refuses what checkDestination refuses, for what never
// passes the router: a UDP session sends each packet where it says, and only
// the first destination is routed.
type privateFilterDialer struct {
	N.Dialer
	// passDomains leaves domains to a front proxy that resolves them itself.
	passDomains bool
}

func (d *privateFilterDialer) refuses(destination M.Socksaddr) bool {
	if destination.IsFqdn() {
		return !d.passDomains
	}
	// An unresolved domain written to a UDP socket arrives with no address,
	// which the kernel sends to the node itself.
	return !destination.Addr.IsValid() || privateAddress(destination.Addr)
}

func (d *privateFilterDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.refuses(destination) {
		return nil, E.New("private destination refused: ", destination)
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *privateFilterDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.refuses(destination) {
		return nil, E.New("private destination refused: ", destination)
	}
	conn, err := d.Dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return &privateFilterPacketConn{NetPacketConn: bufio.NewPacketConn(conn), dialer: d}, nil
}

// privateFilterPacketConn drops packets to refused destinations, as a
// firewall would, so that the rest of the session carries on.
type privateFilterPacketConn struct {
	N.NetPacketConn
	dialer *privateFilterDialer
}

func (c *privateFilterPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.dialer.refuses(destination) {
		buffer.Release()
		return nil
	}
	return c.NetPacketConn.WritePacket(buffer, destination)
}

func (c *privateFilterPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.dialer.refuses(M.SocksaddrFromNet(addr)) {
		return len(p), nil
	}
	return c.NetPacketConn.WriteTo(p, addr)
}
