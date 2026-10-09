package nextserver

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/The-NeXT-Project/NeXT-Server/option"
)

func TestPrivateAddress(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fc00::1",
		"169.254.169.254", "fe80::1", "100.64.0.1", "0.0.0.0", "0.1.2.3", "::",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "224.0.0.1", "ff02::1", "255.255.255.255",
	} {
		if !privateAddress(netip.MustParseAddr(address)) {
			t.Error(address, " is not private")
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111", "100.128.0.1", "172.32.0.1", "::ffff:1.1.1.1"} {
		if privateAddress(netip.MustParseAddr(address)) {
			t.Error(address, " is private")
		}
	}
}

func TestCheckDestination(t *testing.T) {
	server := &Server{}
	metadata := boxAdapter.InboundContext{
		Destination:          M.ParseSocksaddrHostPort("example.com", 443),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("93.184.215.14")},
	}
	if err := server.checkDestination(&metadata); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(metadata.DestinationAddresses, []netip.Addr{netip.MustParseAddr("93.184.215.14")}) {
		t.Error("kept ", metadata.DestinationAddresses)
	}
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if server.checkDestination(&metadata) == nil {
		t.Error("allowed a domain with private addresses only")
	}
	metadata = boxAdapter.InboundContext{Destination: M.ParseSocksaddrHostPort("169.254.169.254", 80)}
	if server.checkDestination(&metadata) == nil {
		t.Error("allowed the metadata service")
	}
	server.options = option.ServerOptions{AllowPrivateDestinations: true}
	if err := server.checkDestination(&metadata); err != nil {
		t.Error("refused with allow_private_destinations: ", err)
	}
}

type recordingPacketConn struct {
	net.PacketConn
	written []string
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.written = append(c.written, addr.String())
	return len(p), nil
}

type packetDialer struct {
	N.Dialer
	conn *recordingPacketConn
}

func (d packetDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.conn, nil
}

// Packets after the first in a UDP session go where they say, past the router.
func TestPrivateFilterDropsLaterPackets(t *testing.T) {
	recorder := &recordingPacketConn{}
	dialer := &privateFilterDialer{Dialer: packetDialer{conn: recorder}}
	if _, err := dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53)); err == nil {
		t.Fatal("listened for a private first destination")
	}
	conn, err := dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("1.1.1.1", 53))
	if err != nil {
		t.Fatal(err)
	}
	packetConn := conn.(N.NetPacketConn)
	for _, destination := range []M.Socksaddr{
		M.ParseSocksaddrHostPort("1.1.1.1", 53),
		M.ParseSocksaddrHostPort("127.0.0.1", 22),
		M.ParseSocksaddrHostPort("example.com", 53),
		M.ParseSocksaddrHostPort("8.8.8.8", 53),
	} {
		if err = packetConn.WritePacket(buf.As([]byte("ping")).ToOwned(), destination); err != nil {
			t.Fatal(err)
		}
	}
	// An unresolved domain reaches WriteTo without an address.
	packetConn.WriteTo([]byte("ping"), &net.UDPAddr{Port: 22})
	if !slices.Equal(recorder.written, []string{"1.1.1.1:53", "8.8.8.8:53"}) {
		t.Error("wrote to ", recorder.written)
	}
}
