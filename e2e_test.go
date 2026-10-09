package nextserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	nextserver "github.com/The-NeXT-Project/NeXT-Server"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	boxOption "github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const panelKey = "node-key"

// fakePanel implements NeXT-Panel Server API V1 the way ServerApiV1.php does.
type fakePanel struct {
	t      *testing.T
	access sync.Mutex

	info       map[string]any
	users      []map[string]any
	rules      []map[string]any
	usersError string

	heartbeats  int
	notModified int
	traffic     map[int][2]int64
	online      map[int]map[string]bool
	detectLogs  map[[2]int]bool
}

func newFakePanel(t *testing.T, sort int, customConfig map[string]any, users []map[string]any) (*fakePanel, *httptest.Server) {
	panel := &fakePanel{
		t: t,
		info: map[string]any{
			"node_speedlimit": 0,
			"sort":            sort,
			"server":          "127.0.0.1",
			"custom_config":   customConfig,
			"type":            "NeXT-Panel",
			"version":         "test",
		},
		users:      users,
		rules:      []map[string]any{},
		traffic:    make(map[int][2]int64),
		online:     make(map[int]map[string]bool),
		detectLogs: make(map[[2]int]bool),
	}
	server := httptest.NewServer(panel)
	t.Cleanup(server.Close)
	return panel, server
}

func (p *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.access.Lock()
	defer p.access.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fail := func(status int, code string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": code}})
	}
	if r.Header.Get("Authorization") != "Bearer "+panelKey {
		fail(http.StatusUnauthorized, "unauthenticated")
		return
	}
	withETag := func(data any) {
		content, _ := json.Marshal(data)
		sum := sha256.Sum256(content)
		etag := `W/"` + hex.EncodeToString(sum[:8]) + `"`
		if r.Header.Get("If-None-Match") == etag {
			p.notModified++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	}
	var body map[string][]map[string]any
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(http.StatusBadRequest, "invalid_body")
			return
		}
	}
	userID := func(entry map[string]any) int {
		id, ok := entry["user_id"].(float64)
		if !ok || id <= 0 {
			p.t.Errorf("report entry without a valid user_id: %v", entry)
		}
		return int(id)
	}
	switch r.Method + " " + r.URL.Path {
	case "PUT /api/server/v1/heartbeat":
		p.heartbeats++
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"timestamp": time.Now().Unix()}})
	case "GET /api/server/v1/info":
		withETag(p.info)
	case "GET /api/server/v1/users":
		if p.usersError != "" {
			fail(http.StatusForbidden, p.usersError)
			return
		}
		withETag(p.users)
	case "GET /api/server/v1/detect_rules":
		withETag(p.rules)
	case "POST /api/server/v1/users/traffic":
		for _, entry := range body["traffic"] {
			id := userID(entry)
			current := p.traffic[id]
			current[0] += int64(entry["u"].(float64))
			current[1] += int64(entry["d"].(float64))
			p.traffic[id] = current
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accepted": len(body["traffic"])}})
	case "POST /api/server/v1/users/online":
		for _, entry := range body["online"] {
			id := userID(entry)
			if p.online[id] == nil {
				p.online[id] = make(map[string]bool)
			}
			p.online[id][entry["ip"].(string)] = true
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accepted": len(body["online"])}})
	case "POST /api/server/v1/users/detect_logs":
		for _, entry := range body["logs"] {
			p.detectLogs[[2]int{userID(entry), int(entry["rule_id"].(float64))}] = true
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accepted": len(body["logs"])}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *fakePanel) update(f func(p *fakePanel)) {
	p.access.Lock()
	defer p.access.Unlock()
	f(p)
}

func (p *fakePanel) read(f func(p *fakePanel) bool) bool {
	p.access.Lock()
	defer p.access.Unlock()
	return f(p)
}

func eventually(t *testing.T, timeout time.Duration, message string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for ", message)
}

func freePort(t *testing.T) int {
	t.Helper()
	for {
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpListener.Addr().(*net.TCPAddr).Port
		udpListener, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		tcpListener.Close()
		if err == nil {
			udpListener.Close()
			return port
		}
	}
}

func startNextServer(t *testing.T, panelURL string, configure func(*option.ServerOptions)) {
	t.Helper()
	listen := badoption.Addr(M.ParseAddr("127.0.0.1"))
	serverOptions := option.ServerOptions{
		URL:          panelURL,
		Key:          panelKey,
		PullInterval: badoption.Duration(150 * time.Millisecond),
		PushInterval: badoption.Duration(150 * time.Millisecond),
		// Every test destination is on loopback.
		AllowPrivateDestinations: true,
	}
	serverOptions.Listen = &listen
	if configure != nil {
		configure(&serverOptions)
	}
	instance, err := nextserver.New(context.Background(), option.Options{
		Log:     &boxOption.LogOptions{Level: logLevel()},
		Servers: []option.ServerOptions{serverOptions},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
}

func logLevel() string {
	if level := os.Getenv("NEXT_SERVER_TEST_LOG"); level != "" {
		return level
	}
	return "error"
}

// clientContextAccess serializes include.Context, which assigns a package
// variable on each call when built without with_quic. Every client still
// needs its own context: sing-box registers its managers in it.
var clientContextAccess sync.Mutex

func clientContext() context.Context {
	clientContextAccess.Lock()
	defer clientContextAccess.Unlock()
	return include.Context(context.Background())
}

// startClient runs a sing-box client with outbound as the only route, behind
// a SOCKS inbound, and returns a dialer for it.
func startClient(t *testing.T, outbound map[string]any) N.Dialer {
	t.Helper()
	socksPort := freePort(t)
	outbound["tag"] = "proxy"
	config := map[string]any{
		"log": map[string]any{"level": logLevel()},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"final": "proxy"},
	}
	content, _ := json.Marshal(config)
	ctx := clientContext()
	options, err := singJSON.UnmarshalExtendedContext[boxOption.Options](ctx, content)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(socksPort)), socks.Version5, "", "")
}

func startEcho(t *testing.T) (tcpPort int, udpPort int) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcpListener.Close() })
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpConn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := udpConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpConn.WriteTo(buffer[:n], addr)
		}
	}()
	return tcpListener.Addr().(*net.TCPAddr).Port, udpConn.LocalAddr().(*net.UDPAddr).Port
}

func echoTCP(t *testing.T, dialer N.Dialer, destination M.Socksaddr, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	rand.Read(payload)
	go conn.Write(payload)
	received := make([]byte, size)
	if _, err = io.ReadFull(conn, received); err != nil {
		t.Fatal("read echo: ", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("echo mismatch")
	}
}

func echoUDP(t *testing.T, dialer N.Dialer, destination M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal("listen packet: ", err)
	}
	defer conn.Close()
	payload := make([]byte, 1000)
	rand.Read(payload)
	received := make([]byte, 2048)
	// UDP may drop the first datagram while the session is set up.
	for attempt := 0; attempt < 5; attempt++ {
		if _, err = conn.WriteTo(payload, destination.UDPAddr()); err != nil {
			t.Fatal("write packet: ", err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFrom(received)
		if err == nil {
			if !bytes.Equal(payload, received[:n]) {
				t.Fatal("udp echo mismatch")
			}
			return
		}
	}
	t.Fatal("no udp echo: ", err)
}

type protocolCase struct {
	name     string
	sort     int
	custom   func(port int) map[string]any
	outbound func(port int) map[string]any
	noUDP    bool
	// quic cases need sing-box's QUIC clients, built with -tags with_quic.
	quic bool
}

var (
	userUUID     = "b831381d-6324-4d53-ad4f-8cda48b30811"
	userPassword = "user-password"
	ss2022Server = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ss2022User   = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
)

func testUsers() []map[string]any {
	return []map[string]any{
		{"id": 1, "node_speedlimit": 0, "uuid": userUUID, "passwd": userPassword},
		{"id": 2, "node_speedlimit": 0, "uuid": "6d5c2f4b-1f2e-4c6d-9a1b-2c3d4e5f6a7b", "passwd": "other"},
	}
}

func insecureTLS() map[string]any {
	return map[string]any{"enabled": true, "server_name": "node.example.com", "insecure": true}
}

// The outbounds mirror what NeXT-Panel's sing-box subscription generates.
var protocolCases = []protocolCase{
	{
		name: "shadowsocks2022",
		sort: 1,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": strconv.Itoa(port), "method": "2022-blake3-aes-128-gcm", "server_key": ss2022Server}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": port,
				"method": "2022-blake3-aes-128-gcm", "password": ss2022Server + ":" + ss2022User}
		},
	},
	{
		name: "vmess",
		sort: 11,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "network": "tcp"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "security": "auto", "alter_id": 0}
		},
	},
	{
		name: "vmess-ws-tls",
		sort: 11,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "network": "ws", "security": "tls", "host": "node.example.com", "path": "/ws"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "security": "auto",
				"tls": insecureTLS(), "transport": map[string]any{"type": "ws", "path": "/ws"}}
		},
	},
	{
		name: "trojan",
		sort: 14,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port, "password": userUUID, "tls": insecureTLS()}
		},
	},
	{
		name: "trojan-grpc",
		sort: 14,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com", "network": "grpc", "servicename": "svc"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port, "password": userUUID, "tls": insecureTLS(),
				"transport": map[string]any{"type": "grpc", "service_name": "svc"}}
		},
	},
	{
		name: "tuic",
		quic: true,
		sort: 2,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "tuic", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "password": userPassword,
				"congestion_control": "bbr", "zero_rtt_handshake": true, "tls": insecureTLS()}
		},
	},
	{
		// mihomo offers h3, which the server must then select.
		name: "tuic-alpn-h3",
		quic: true,
		sort: 2,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com"}
		},
		outbound: func(port int) map[string]any {
			tlsOptions := insecureTLS()
			tlsOptions["alpn"] = []string{"h3"}
			return map[string]any{"type": "tuic", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "password": userPassword,
				"congestion_control": "bbr", "tls": tlsOptions}
		},
	},
	{
		name: "hysteria2",
		quic: true,
		sort: 4,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com", "obfs_password": "obfs-secret"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "hysteria2", "server": "127.0.0.1", "server_port": port, "password": userPassword,
				"tls": insecureTLS(), "obfs": map[string]any{"type": "salamander", "password": "obfs-secret"}}
		},
	},
	{
		name: "anytls",
		sort: 5,
		custom: func(port int) map[string]any {
			return map[string]any{"offset_port_node": port, "host": "node.example.com"}
		},
		outbound: func(port int) map[string]any {
			return map[string]any{"type": "anytls", "server": "127.0.0.1", "server_port": port, "password": userPassword, "tls": insecureTLS()}
		},
	},
}

func TestProtocols(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	for _, testCase := range protocolCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.quic && !C.WithQUIC {
				t.Skip("built without with_quic")
			}
			t.Parallel()
			port := freePort(t)
			users := testUsers()
			if testCase.sort == 1 {
				for _, user := range users {
					user["passwd"] = ss2022User
					if user["id"] == 2 {
						user["passwd"] = base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
					}
				}
			}
			panel, panelServer := newFakePanel(t, testCase.sort, testCase.custom(port), users)
			startNextServer(t, panelServer.URL, nil)
			dialer := startClient(t, testCase.outbound(port))

			// A domain destination exercises the server's own resolution.
			echoTCP(t, dialer, M.ParseSocksaddrHostPort("localhost", uint16(tcpEcho)), 256*1024)
			if !testCase.noUDP {
				echoUDP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(udpEcho)))
			}

			eventually(t, 5*time.Second, "traffic, online and heartbeat reports", func() bool {
				return panel.read(func(p *fakePanel) bool {
					traffic := p.traffic[1]
					return traffic[0] >= 256*1024 && traffic[1] >= 256*1024 &&
						p.online[1]["127.0.0.1"] && p.heartbeats > 0
				})
			})
			panel.read(func(p *fakePanel) bool {
				if _, reported := p.traffic[2]; reported {
					t.Error("traffic reported for a user that sent nothing")
				}
				if p.notModified == 0 {
					t.Error("polls never sent If-None-Match")
				}
				return true
			})
		})
	}
}

func TestWrongCredentialRejected(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port := freePort(t)
	_, panelServer := newFakePanel(t, 14, map[string]any{"offset_port_node": port, "host": "node.example.com"}, testUsers())
	startNextServer(t, panelServer.URL, nil)
	dialer := startClient(t, map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port,
		"password": "00000000-0000-0000-0000-000000000000", "tls": insecureTLS()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("hello"))
		if _, err = conn.Read(make([]byte, 5)); err == nil {
			t.Fatal("unknown user got an echo")
		}
	}
}

func TestDetectRuleBlocksAndReports(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port := freePort(t)
	panel, panelServer := newFakePanel(t, 11, map[string]any{"offset_port_node": port}, testUsers())
	panel.rules = []map[string]any{
		{"id": 7, "name": "blocked", "text": "", "regex": `(^|\.)blocked\.example$`, "type": 1},
		{"id": 8, "name": "hex", "text": "", "regex": `^deadbeef`, "type": 2},
		{"id": 9, "name": "broken", "text": "", "regex": `(`, "type": 1},
	}
	startNextServer(t, panelServer.URL, nil)
	dialer := startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "security": "auto"})

	expectBlocked := func(destination M.Socksaddr, payload []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write(payload)
		if _, err = io.ReadFull(conn, make([]byte, len(payload))); err == nil {
			t.Fatal("blocked connection to ", destination, " got an echo")
		}
	}
	expectBlocked(M.ParseSocksaddrHostPort("www.blocked.example", 80), []byte("GET / HTTP/1.1\r\n\r\n"))
	expectBlocked(M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3})
	// Other traffic still passes, and the invalid rule did not stop the valid ones.
	echoTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), 1024)

	eventually(t, 5*time.Second, "detect logs", func() bool {
		return panel.read(func(p *fakePanel) bool {
			return p.detectLogs[[2]int{1, 7}] && p.detectLogs[[2]int{1, 8}]
		})
	})
}

func TestRemovedUserIsDisconnected(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port := freePort(t)
	panel, panelServer := newFakePanel(t, 14, map[string]any{"offset_port_node": port, "host": "node.example.com"}, testUsers())
	startNextServer(t, panelServer.URL, nil)
	dialer := startClient(t, map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port, "password": userUUID, "tls": insecureTLS()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}

	// The panel stops serving user 1, as it does when their traffic runs out.
	panel.update(func(p *fakePanel) { p.users = p.users[1:] })
	closed := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		closed <- err
	}()
	select {
	case err = <-closed:
		if err == nil {
			t.Fatal("read succeeded after the user was removed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection of a removed user stayed open")
	}
	// Traffic from before the removal is still reported.
	eventually(t, 5*time.Second, "traffic of the removed user", func() bool {
		return panel.read(func(p *fakePanel) bool { return p.traffic[1][0] >= 4 })
	})
}

func TestOutOfBandwidthStopsUsers(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port := freePort(t)
	panel, panelServer := newFakePanel(t, 11, map[string]any{"offset_port_node": port}, testUsers())
	startNextServer(t, panelServer.URL, nil)
	dialer := startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "security": "auto"})
	echoTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), 1024)

	panel.update(func(p *fakePanel) { p.usersError = "out_of_bandwidth" })
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("hello"))
		if _, err = io.ReadFull(conn, make([]byte, 5)); err == nil {
			t.Fatal("node kept serving after out_of_bandwidth")
		}
	}

	// Serving resumes with the same user list once the panel allows it again.
	panel.update(func(p *fakePanel) { p.usersError = "" })
	eventually(t, 5*time.Second, "users to be served again", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte("hello"))
		_, err = io.ReadFull(conn, make([]byte, 5))
		return err == nil
	})
}

func TestSpeedLimit(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port := freePort(t)
	users := testUsers()
	// 2 Mbps is 250 kB/s each way.
	users[0]["node_speedlimit"] = 2
	_, panelServer := newFakePanel(t, 11, map[string]any{"offset_port_node": port}, users)
	startNextServer(t, panelServer.URL, nil)
	dialer := startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID, "security": "auto"})

	start := time.Now()
	// The first 250 kB pass as the initial burst; the rest at the rate.
	echoTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), 750*1000)
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatal("750 kB at 250 kB/s took only ", elapsed)
	}
}

func TestListenerRestartKeepsUsers(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	port, newPort := freePort(t), freePort(t)
	panel, panelServer := newFakePanel(t, 11, map[string]any{"offset_port_node": port}, testUsers())
	startNextServer(t, panelServer.URL, nil)
	echoTCP(t, startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": port, "uuid": userUUID}),
		M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), 1024)

	// Moving the port rebuilds the listener; it must come up with the users
	// it already had, although the user list itself did not change.
	panel.update(func(p *fakePanel) { p.info["custom_config"] = map[string]any{"offset_port_node": newPort} })
	dialer := startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": newPort, "uuid": userUUID})
	eventually(t, 5*time.Second, "the moved listener to serve existing users", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte("hello"))
		_, err = io.ReadFull(conn, make([]byte, 5))
		return err == nil
	})
}

// proxyRelay forwards to target, announcing source in a PROXY v1 header.
func proxyRelay(t *testing.T, target int, source string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				upstream, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(target))
				if err != nil {
					return
				}
				defer upstream.Close()
				upstream.Write([]byte("PROXY TCP4 " + source + " 127.0.0.1 40000 " + strconv.Itoa(target) + "\r\n"))
				go io.Copy(upstream, conn)
				io.Copy(conn, upstream)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestProxyProtocol(t *testing.T) {
	tcpEcho, _ := startEcho(t)
	for _, testCase := range []struct {
		name    string
		trusted []string
		want    string
	}{
		{"trusted", nil, "203.0.113.9"},
		{"untrusted relay", []string{"192.0.2.0/24"}, "127.0.0.1"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			port := freePort(t)
			panel, panelServer := newFakePanel(t, 11, map[string]any{"offset_port_node": port}, testUsers())
			startNextServer(t, panelServer.URL, func(options *option.ServerOptions) {
				options.ProxyProtocol = true
				options.ProxyProtocolTrusted = testCase.trusted
			})
			relay := proxyRelay(t, port, "203.0.113.9")
			dialer := startClient(t, map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": relay, "uuid": userUUID})
			echoTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)), 1024)
			eventually(t, 5*time.Second, "online address "+testCase.want, func() bool {
				return panel.read(func(p *fakePanel) bool { return p.online[1][testCase.want] })
			})
			panel.read(func(p *fakePanel) bool {
				if len(p.online[1]) != 1 {
					t.Error("online addresses: ", p.online[1])
				}
				return true
			})
		})
	}
}
