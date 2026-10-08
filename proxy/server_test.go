package proxy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

// This package does not import sing-box's include package, so it sees only
// what the server binary registers itself.
func TestQUICTransport(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()
	var server inbound.NodeOptions
	server.Context = context.Background()
	server.Logger = log.NewNOPFactory().Logger()
	server.Server.Listen = common.Ptr(badoption.Addr(M.ParseAddr("127.0.0.1")))
	server.Config = &adapter.NodeConfig{
		Type:       adapter.NodeTypeVMess,
		ListenPort: uint16(port),
		TLS:        &boxOption.InboundTLSOptions{Enabled: true, Insecure: true},
		Transport:  &boxOption.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC},
	}
	nodeServer, err := New(server)
	if !C.WithQUIC {
		if !errors.Is(err, C.ErrQUICNotIncluded) {
			t.Fatal("without with_quic: ", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer nodeServer.Close()
	// Closing right after starting also covers the transport's listener
	// being set up in its serving goroutine.
	if err = nodeServer.Start(); err != nil {
		t.Fatal(err)
	}
}
