package abuse

import (
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

var start = time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)

func destination(host string, port uint16) M.Socksaddr {
	return M.ParseSocksaddrHostPort(host, port)
}

func TestFloodPerDestination(t *testing.T) {
	limits := &Limits{FloodWindow: 10 * time.Second, ConnectionsPerDestination: 3}
	var tracker Tracker
	target := destination("203.0.113.1", 443)
	for i := 0; i < 3; i++ {
		if verdict, crossed := tracker.Connect(limits, start, target); crossed {
			t.Fatal("crossed at connection ", i+1, ": ", verdict.Reason)
		}
	}
	// Other destinations have their own count.
	if _, crossed := tracker.Connect(limits, start, destination("203.0.113.2", 443)); crossed {
		t.Fatal("another destination crossed")
	}
	verdict, crossed := tracker.Connect(limits, start.Add(9*time.Second), target)
	if !crossed || verdict.Kind != Flood || !strings.Contains(verdict.Reason, "203.0.113.1:443") {
		t.Fatalf("fourth connection within the window: %v %+v", crossed, verdict)
	}
	// Crossing starts afresh, and a new window forgets the old count.
	for i := 0; i < 3; i++ {
		tracker.Connect(limits, start.Add(9*time.Second), target)
	}
	if _, crossed := tracker.Connect(limits, start.Add(20*time.Second), target); crossed {
		t.Fatal("the count carried over into a new window")
	}
}

func TestFloodTotal(t *testing.T) {
	limits := &Limits{FloodWindow: 10 * time.Second, Connections: 5}
	var tracker Tracker
	for i := 0; i < 5; i++ {
		if _, crossed := tracker.Connect(limits, start, destination("203.0.113.1", uint16(1000+i))); crossed {
			t.Fatal("crossed early")
		}
	}
	if verdict, crossed := tracker.Connect(limits, start, destination("198.51.100.1", 80)); !crossed || verdict.Kind != Flood {
		t.Fatal("sixth connection did not cross")
	}
}

func TestPortsPerHost(t *testing.T) {
	limits := &Limits{ScanWindow: time.Minute, PortsPerHost: 3}
	var tracker Tracker
	for port := uint16(1); port <= 3; port++ {
		// Repeated connections to one port count once.
		for i := 0; i < 5; i++ {
			if _, crossed := tracker.Connect(limits, start, destination("203.0.113.1", port)); crossed {
				t.Fatal("crossed early")
			}
		}
	}
	// IPv4-mapped IPv6 is the same host.
	verdict, crossed := tracker.Connect(limits, start, destination("::ffff:203.0.113.1", 4))
	if !crossed || verdict.Kind != PortScan || !strings.Contains(verdict.Reason, "4 ports of 203.0.113.1") {
		t.Fatalf("fourth port: %v %+v", crossed, verdict)
	}
}

func TestFailedDestinations(t *testing.T) {
	limits := &Limits{ScanWindow: time.Minute, FailedDestinations: 3}
	var tracker Tracker
	for i := 0; i < 3; i++ {
		for repeat := 0; repeat < 3; repeat++ {
			if _, crossed := tracker.Fail(limits, start, destination("203.0.113.1", uint16(22+i))); crossed {
				t.Fatal("crossed early")
			}
		}
	}
	if _, crossed := tracker.Fail(limits, start.Add(time.Minute), destination("203.0.113.9", 22)); crossed {
		t.Fatal("the count carried over into a new window")
	}
	for i := 0; i < 2; i++ {
		tracker.Fail(limits, start.Add(time.Minute), destination("203.0.113.10", uint16(22+i)))
	}
	if verdict, crossed := tracker.Fail(limits, start.Add(time.Minute), destination("203.0.113.11", 22)); !crossed || verdict.Kind != PortScan {
		t.Fatal("fourth failed destination did not cross")
	}
}

func TestDisabledLimits(t *testing.T) {
	var tracker Tracker
	limits := &Limits{}
	for i := 0; i < 10000; i++ {
		if _, crossed := tracker.Connect(limits, start, destination("203.0.113.1", uint16(i))); crossed {
			t.Fatal("crossed without limits")
		}
		if _, crossed := tracker.Fail(limits, start, destination("203.0.113.1", uint16(i))); crossed {
			t.Fatal("crossed without limits")
		}
	}
}

func TestMemoryBound(t *testing.T) {
	limits := &Limits{ScanWindow: time.Minute, FailedDestinations: 1 << 30, FloodWindow: time.Minute, ConnectionsPerDestination: 1 << 30, PortsPerHost: 1 << 30}
	var tracker Tracker
	for i := 0; i < 3*maxKeys; i++ {
		target := destination("203.0.113.1", uint16(i))
		tracker.Connect(limits, start, target)
		tracker.Fail(limits, start, target)
	}
	if len(tracker.scan.failed) > maxKeys || len(tracker.scan.hostPorts) > maxKeys || len(tracker.flood.destinations) > maxKeys {
		t.Fatal("a window grew past maxKeys")
	}
}

func TestBanAndNotice(t *testing.T) {
	var tracker Tracker
	if tracker.Banned(start) {
		t.Fatal("banned from the start")
	}
	tracker.Ban(start.Add(time.Minute))
	if !tracker.Banned(start.Add(59*time.Second)) || tracker.Banned(start.Add(time.Minute)) {
		t.Fatal("ban does not last exactly a minute")
	}
	if !tracker.Notice(BitTorrent, start, time.Minute) {
		t.Fatal("first hit not noticed")
	}
	if tracker.Notice(BitTorrent, start.Add(30*time.Second), time.Minute) {
		t.Fatal("repeat within the interval noticed")
	}
	if !tracker.Notice(BlockedPort, start.Add(30*time.Second), time.Minute) {
		t.Fatal("another kind shares the interval")
	}
	if !tracker.Notice(BitTorrent, start.Add(time.Minute), time.Minute) {
		t.Fatal("hit after the interval not noticed")
	}
}
