package abuse

import (
	"sync"
	"sync/atomic"
	"time"

	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
)

// Kind is a kind of abuse.
type Kind int

const (
	P2P Kind = iota
	BlockedPort
	PortScan
	Flood
	BruteForce
	Exploit
	Mining
	Kinds
)

func (k Kind) String() string {
	switch k {
	case P2P:
		return "P2P"
	case BlockedPort:
		return "blocked port"
	case PortScan:
		return "port scan"
	case Flood:
		return "connection flood"
	case BruteForce:
		return "brute force"
	case Exploit:
		return "exploit"
	case Mining:
		return "crypto mining"
	default:
		return "abuse(" + F.ToString(int(k)) + ")"
	}
}

// Limits are the thresholds a Tracker applies. A threshold of 0 is not checked.
type Limits struct {
	ScanWindow         time.Duration
	FailedDestinations int
	PortsPerHost       int

	FloodWindow               time.Duration
	Connections               int
	ConnectionsPerDestination int

	// Login counts apply to connections the caller passes to Login.
	LoginWindow                    time.Duration
	LoginHosts                     int
	LoginConnectionsPerDestination int
}

func (l *Limits) scans() bool {
	return l.FailedDestinations > 0 || l.PortsPerHost > 0
}

func (l *Limits) floods() bool {
	return l.Connections > 0 || l.ConnectionsPerDestination > 0
}

// maxKeys bounds what one window remembers of one user. Past it, new
// destinations go uncounted until the window ends; every threshold is far
// below it, so a user who gets there has crossed one already.
const maxKeys = 4096

// Verdict is a threshold a user crossed.
type Verdict struct {
	Kind   Kind
	Reason string
}

// Tracker follows one user's TCP connections over fixed windows that start
// with the first connection after the previous one ended, and holds their
// ban. Its zero value is ready to use, and it is safe for concurrent use.
type Tracker struct {
	bannedUntil atomic.Int64
	notices     [Kinds]atomic.Int64

	access sync.Mutex
	scan   scanWindow
	flood  floodWindow
	login  loginWindow
}

type scanWindow struct {
	start     time.Time
	failed    map[M.Socksaddr]struct{}
	hostPorts map[M.Socksaddr]struct{}
	// ports counts the distinct ports per host, keyed with port 0.
	ports map[M.Socksaddr]int
}

type loginWindow struct {
	start time.Time
	// hosts holds the hosts reached on login ports, keyed with port 0.
	hosts        map[M.Socksaddr]struct{}
	destinations map[M.Socksaddr]int
}

type floodWindow struct {
	start        time.Time
	total        int
	destinations map[M.Socksaddr]int
}

func normalize(destination M.Socksaddr) M.Socksaddr {
	destination.Addr = destination.Addr.Unmap()
	return destination
}

// Connect counts a new connection to destination, and returns the threshold
// it crossed, if any. Crossing one starts the user's windows afresh.
func (t *Tracker) Connect(limits *Limits, now time.Time, destination M.Socksaddr) (Verdict, bool) {
	if !limits.floods() && limits.PortsPerHost <= 0 {
		return Verdict{}, false
	}
	destination = normalize(destination)
	t.access.Lock()
	defer t.access.Unlock()
	if limits.floods() {
		window := &t.flood
		if now.Sub(window.start) >= limits.FloodWindow {
			*window = floodWindow{start: now}
		}
		window.total++
		if limits.Connections > 0 && window.total > limits.Connections {
			return t.trip(Flood, F.ToString(window.total, " connections within ", limits.FloodWindow.String()))
		}
		if limits.ConnectionsPerDestination > 0 {
			count, seen := window.destinations[destination]
			if seen || len(window.destinations) < maxKeys {
				if window.destinations == nil {
					window.destinations = make(map[M.Socksaddr]int)
				}
				count++
				window.destinations[destination] = count
			}
			if count > limits.ConnectionsPerDestination {
				return t.trip(Flood, F.ToString(count, " connections to ", destination.String(), " within ", limits.FloodWindow.String()))
			}
		}
	}
	if limits.PortsPerHost > 0 {
		window := t.scanWindow(limits, now)
		if _, seen := window.hostPorts[destination]; !seen && len(window.hostPorts) < maxKeys {
			if window.hostPorts == nil {
				window.hostPorts = make(map[M.Socksaddr]struct{})
				window.ports = make(map[M.Socksaddr]int)
			}
			window.hostPorts[destination] = struct{}{}
			host := destination
			host.Port = 0
			window.ports[host]++
			if window.ports[host] > limits.PortsPerHost {
				return t.trip(PortScan, F.ToString(window.ports[host], " ports of ", host.AddrString(), " within ", limits.ScanWindow.String()))
			}
		}
	}
	return Verdict{}, false
}

// Login counts a new connection to a login port (SSH, RDP, databases and the
// like): reaching many hosts on such ports is credential spraying, and
// connecting to one over and over is hammering it with passwords.
func (t *Tracker) Login(limits *Limits, now time.Time, destination M.Socksaddr) (Verdict, bool) {
	if limits.LoginHosts <= 0 && limits.LoginConnectionsPerDestination <= 0 {
		return Verdict{}, false
	}
	destination = normalize(destination)
	host := destination
	host.Port = 0
	t.access.Lock()
	defer t.access.Unlock()
	window := &t.login
	if now.Sub(window.start) >= limits.LoginWindow {
		*window = loginWindow{start: now}
	}
	if limits.LoginHosts > 0 {
		if _, seen := window.hosts[host]; !seen && len(window.hosts) < maxKeys {
			if window.hosts == nil {
				window.hosts = make(map[M.Socksaddr]struct{})
			}
			window.hosts[host] = struct{}{}
			if len(window.hosts) > limits.LoginHosts {
				return t.trip(BruteForce, F.ToString(len(window.hosts), " hosts on login ports within ", limits.LoginWindow.String()))
			}
		}
	}
	if limits.LoginConnectionsPerDestination > 0 {
		count, seen := window.destinations[destination]
		if seen || len(window.destinations) < maxKeys {
			if window.destinations == nil {
				window.destinations = make(map[M.Socksaddr]int)
			}
			count++
			window.destinations[destination] = count
		}
		if count > limits.LoginConnectionsPerDestination {
			return t.trip(BruteForce, F.ToString(count, " connections to ", destination.String(), " within ", limits.LoginWindow.String()))
		}
	}
	return Verdict{}, false
}

// Fail counts a connection to destination that could not be opened.
func (t *Tracker) Fail(limits *Limits, now time.Time, destination M.Socksaddr) (Verdict, bool) {
	if limits.FailedDestinations <= 0 {
		return Verdict{}, false
	}
	destination = normalize(destination)
	t.access.Lock()
	defer t.access.Unlock()
	window := t.scanWindow(limits, now)
	if _, seen := window.failed[destination]; seen || len(window.failed) >= maxKeys {
		return Verdict{}, false
	}
	if window.failed == nil {
		window.failed = make(map[M.Socksaddr]struct{})
	}
	window.failed[destination] = struct{}{}
	if len(window.failed) > limits.FailedDestinations {
		return t.trip(PortScan, F.ToString(len(window.failed), " unreachable destinations within ", limits.ScanWindow.String()))
	}
	return Verdict{}, false
}

func (t *Tracker) scanWindow(limits *Limits, now time.Time) *scanWindow {
	if now.Sub(t.scan.start) >= limits.ScanWindow {
		t.scan = scanWindow{start: now}
	}
	return &t.scan
}

// trip starts the windows afresh, so that one burst gives one verdict and
// its memory is freed. The caller holds access.
func (t *Tracker) trip(kind Kind, reason string) (Verdict, bool) {
	t.scan = scanWindow{}
	t.flood = floodWindow{}
	t.login = loginWindow{}
	return Verdict{Kind: kind, Reason: reason}, true
}

// Ban refuses the user until the given time.
func (t *Tracker) Ban(until time.Time) {
	t.bannedUntil.Store(until.UnixNano())
}

// Banned reports whether the user is banned at now.
func (t *Tracker) Banned(now time.Time) bool {
	return now.UnixNano() < t.bannedUntil.Load()
}

// Notice reports whether a hit of kind at now is the first in interval, so
// that a user hitting a check over and over is logged and reported once.
func (t *Tracker) Notice(kind Kind, now time.Time, interval time.Duration) bool {
	last := t.notices[kind].Load()
	if last != 0 && now.UnixNano()-last < int64(interval) {
		return false
	}
	return t.notices[kind].CompareAndSwap(last, now.UnixNano())
}
