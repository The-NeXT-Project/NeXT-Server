package nextserver

import (
	"bytes"
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// decodeAbuse decodes an abuse section the way the command decodes the file.
func decodeAbuse(t *testing.T, content string) *option.AbuseOptions {
	t.Helper()
	var options option.ServerOptions
	decoder := json.NewDecoder(json.NewCommentFilter(strings.NewReader(`{"url": "", "key": "", "abuse": ` + content + `}`)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&options); err != nil {
		t.Fatal(err)
	}
	return options.Abuse
}

func TestAbuseGuardOptions(t *testing.T) {
	logger := log.NewNOPFactory().Logger()

	guard, err := newAbuseGuard(nil, logger, newAuditor())
	if err != nil {
		t.Fatal(err)
	}
	if !guard.p2p || !slices.Equal(guard.blockedPorts, constant.DefaultBlockedPorts) ||
		!slices.Equal(guard.loginPorts, constant.DefaultLoginPorts) ||
		guard.limits.LoginHosts != constant.DefaultBruteForceHosts ||
		guard.limits.FailedDestinations != constant.DefaultPortScanFailedDestinations ||
		guard.limits.ConnectionsPerDestination != constant.DefaultFloodConnectionsPerDestination ||
		guard.banDuration != constant.DefaultAbuseBanDuration {
		t.Fatalf("defaults not applied: %+v", guard)
	}

	guard, err = newAbuseGuard(decodeAbuse(t, `{"disabled": true}`), logger, newAuditor())
	if err != nil {
		t.Fatal(err)
	}
	if guard.p2p || len(guard.blockedPorts) > 0 || len(guard.loginPorts) > 0 || guard.watchesDials() || guard.limits.Connections > 0 || guard.signatures != nil {
		t.Fatalf("disabled guard still checks: %+v", guard)
	}

	// An empty list is not the same as leaving it out.
	guard, err = newAbuseGuard(decodeAbuse(t, `{
		"blocked_ports": { "ports": [], "rule_id": 3 },
		"port_scan": { "disabled": true },
		"flood": { "window": "1m", "connections_per_destination": 50 }
	}`), logger, newAuditor())
	if err != nil {
		t.Fatal(err)
	}
	if guard.blockedPorts == nil || len(guard.blockedPorts) > 0 {
		t.Fatalf("ports: [] gave %v", guard.blockedPorts)
	}
	if guard.watchesDials() || guard.limits.PortsPerHost > 0 {
		t.Fatal("disabled port scan check still runs")
	}
	if guard.limits.FloodWindow.Minutes() != 1 || guard.limits.ConnectionsPerDestination != 50 ||
		guard.limits.Connections != constant.DefaultFloodConnections {
		t.Fatalf("flood options: %+v", guard.limits)
	}

	for _, invalid := range []string{`{"ban_duration": "-1s"}`, `{"p2p": {"rule_id": -1}}`, `{"mining": {"rule_id": -2}}`, `{"signatures": {"url": "http://example.com/s.json"}}`, `{"brute_force": {"hosts": -1}}`, `{"flood": {"connections": -5}}`} {
		if _, err = newAbuseGuard(decodeAbuse(t, invalid), logger, newAuditor()); err == nil {
			t.Error(invalid, " accepted")
		}
	}
}

// packetSource replays packets, as a client's UDP session would.
type packetSource struct {
	N.PacketConn
	packets []struct {
		destination M.Socksaddr
		payload     []byte
	}
}

func (s *packetSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(s.packets) == 0 {
		return M.Socksaddr{}, context.Canceled
	}
	packet := s.packets[0]
	s.packets = s.packets[1:]
	buffer.Write(packet.payload)
	return packet.destination, nil
}

func TestPacketFilter(t *testing.T) {
	auditor := newAuditor()
	guard, err := newAbuseGuard(decodeAbuse(t, `{"p2p": {"rule_id": 5}, "blocked_ports": {"rule_id": 6}}`), log.NewNOPFactory().Logger(), auditor)
	if err != nil {
		t.Fatal(err)
	}
	user := newUserState(context.Background(), 1)
	source := &packetSource{}
	add := func(destination string, payload string) {
		source.packets = append(source.packets, struct {
			destination M.Socksaddr
			payload     []byte
		}{M.ParseSocksaddr(destination), []byte(payload)})
	}
	add("198.51.100.1:443", "first")
	add("198.51.100.2:6881", "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	add("198.51.100.3:25", "spam")
	add("198.51.100.4:4672", "\xe4\x60")
	add("198.51.100.1:443", "second")
	conn := guard.filterPackets(context.Background(), user, source)

	for _, want := range []string{"first", "second"} {
		buffer := buf.NewPacket()
		// The caller's headroom survives dropped packets.
		buffer.Resize(16, 0)
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer.Bytes(), []byte(want)) || buffer.Start() != 16 || destination.String() != "198.51.100.1:443" {
			t.Fatalf("got %q at %d to %s, want %q", buffer.Bytes(), buffer.Start(), destination, want)
		}
		buffer.Release()
	}
	logs := auditor.collect()
	slices.SortFunc(logs, func(a, b adapter.DetectLog) int { return a.RuleID - b.RuleID })
	if len(logs) != 2 || logs[0].RuleID != 5 || logs[1].RuleID != 6 {
		t.Fatalf("detect logs: %+v", logs)
	}
}

func TestDialFailuresDuringOutage(t *testing.T) {
	guard, err := newAbuseGuard(decodeAbuse(t, `{"port_scan": {"failed_destinations": 2}}`), log.NewNOPFactory().Logger(), newAuditor())
	if err != nil {
		t.Fatal(err)
	}
	user := newUserState(context.Background(), 1)
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	fail := func(port uint16, err error) {
		guard.dialFailed(context.Background(), user, guard.watchDial(nil), M.ParseSocksaddrHostPort("203.0.113.1", port), err)
	}

	// Nothing on the node has got through: its uplink is down, not the user scanning.
	for port := uint16(1); port <= 5; port++ {
		fail(port, refused)
	}
	if user.abuse.Banned(time.Now()) {
		t.Fatal("banned while the node reached nothing")
	}

	guard.lastDial.Store(time.Now().UnixNano())
	// A network the node has no route to says nothing about the user either.
	unreachable := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	for port := uint16(10); port <= 15; port++ {
		fail(port, unreachable)
	}
	fail(20, context.Canceled)
	if user.abuse.Banned(time.Now()) {
		t.Fatal("banned for failures that are the node's")
	}
	for port := uint16(30); port <= 32; port++ {
		fail(port, refused)
	}
	if !user.abuse.Banned(time.Now()) {
		t.Fatal("not banned after three refused destinations")
	}
}

// v1.2.0's only production flood ban was an app retrying an API, 201
// connections in 10 s; the default lets that through.
func TestFloodDefaultAllowsRetryingApps(t *testing.T) {
	guard, err := newAbuseGuard(nil, log.NewNOPFactory().Logger(), newAuditor())
	if err != nil {
		t.Fatal(err)
	}
	user := newUserState(context.Background(), 1)
	api := M.ParseSocksaddrHostPort("open.feishu.cn", 443)
	for i := 0; i < 250; i++ {
		if err = guard.admit(context.Background(), user, N.NetworkTCP, api); err != nil {
			t.Fatal("connection ", i+1, ": ", err)
		}
	}
}
