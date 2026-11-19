package nextserver

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/common/abuse"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// abuseGuard runs the node's own abuse checks (option.AbuseOptions).
// P2P and blocked ports refuse the connection; a port scan, a connection
// flood or brute force bans the user on this node for a while and closes
// their open connections. Hits go to the panel as detect logs of the configured
// rule, at most once per AbuseNoticeInterval per user and kind.
type abuseGuard struct {
	logger  log.ContextLogger
	auditor *auditor

	banDuration time.Duration
	p2p         bool
	// blockedPorts and loginPorts are empty when the check is off.
	blockedPorts []uint16
	loginPorts   []uint16
	limits       abuse.Limits
	ruleIDs      [abuse.Kinds]int
	// signatures holds the exploit and mining signatures of the enabled kinds.
	signatures *signatureSet

	// lastDial is when a dial on this node last got through (UnixNano).
	lastDial atomic.Int64
}

func newAbuseGuard(options *option.AbuseOptions, logger log.ContextLogger, auditor *auditor) (*abuseGuard, error) {
	guard := &abuseGuard{logger: logger, auditor: auditor}
	if options == nil {
		options = &option.AbuseOptions{}
	}
	if options.Disabled {
		return guard, nil
	}
	durations := map[string]time.Duration{
		"ban_duration":       time.Duration(options.BanDuration),
		"port_scan.window":   time.Duration(options.PortScan.Window),
		"flood.window":       time.Duration(options.Flood.Window),
		"brute_force.window": time.Duration(options.BruteForce.Window),
	}
	for name, value := range durations {
		if value < 0 {
			return nil, E.New("abuse.", name, " must not be negative")
		}
	}
	counts := map[string]int{
		"p2p.rule_id":                             options.P2P.RuleID,
		"blocked_ports.rule_id":                   options.BlockedPorts.RuleID,
		"port_scan.rule_id":                       options.PortScan.RuleID,
		"port_scan.failed_destinations":           options.PortScan.FailedDestinations,
		"port_scan.ports_per_host":                options.PortScan.PortsPerHost,
		"flood.rule_id":                           options.Flood.RuleID,
		"flood.connections":                       options.Flood.Connections,
		"flood.connections_per_destination":       options.Flood.ConnectionsPerDestination,
		"brute_force.rule_id":                     options.BruteForce.RuleID,
		"brute_force.hosts":                       options.BruteForce.Hosts,
		"brute_force.connections_per_destination": options.BruteForce.ConnectionsPerDestination,
		"exploits.rule_id":                        options.Exploits.RuleID,
		"mining.rule_id":                          options.Mining.RuleID,
	}
	for name, value := range counts {
		if value < 0 {
			return nil, E.New("abuse.", name, " must not be negative")
		}
	}
	guard.banDuration = orDefault(time.Duration(options.BanDuration), constant.DefaultAbuseBanDuration)
	guard.p2p = !options.P2P.Disabled
	if !options.BlockedPorts.Disabled {
		guard.blockedPorts = options.BlockedPorts.Ports
		if guard.blockedPorts == nil {
			guard.blockedPorts = constant.DefaultBlockedPorts
		}
	}
	if !options.PortScan.Disabled {
		guard.limits.ScanWindow = orDefault(time.Duration(options.PortScan.Window), constant.DefaultPortScanWindow)
		guard.limits.FailedDestinations = orDefault(options.PortScan.FailedDestinations, constant.DefaultPortScanFailedDestinations)
		guard.limits.PortsPerHost = orDefault(options.PortScan.PortsPerHost, constant.DefaultPortScanPortsPerHost)
	}
	if !options.Flood.Disabled {
		guard.limits.FloodWindow = orDefault(time.Duration(options.Flood.Window), constant.DefaultFloodWindow)
		guard.limits.Connections = orDefault(options.Flood.Connections, constant.DefaultFloodConnections)
		guard.limits.ConnectionsPerDestination = orDefault(options.Flood.ConnectionsPerDestination, constant.DefaultFloodConnectionsPerDestination)
	}
	if !options.BruteForce.Disabled {
		guard.loginPorts = options.BruteForce.Ports
		if guard.loginPorts == nil {
			guard.loginPorts = constant.DefaultLoginPorts
		}
		guard.limits.LoginWindow = orDefault(time.Duration(options.BruteForce.Window), constant.DefaultBruteForceWindow)
		guard.limits.LoginHosts = orDefault(options.BruteForce.Hosts, constant.DefaultBruteForceHosts)
		guard.limits.LoginConnectionsPerDestination = orDefault(options.BruteForce.ConnectionsPerDestination, constant.DefaultBruteForceConnectionsPerDestination)
	}
	guard.ruleIDs[abuse.P2P] = options.P2P.RuleID
	guard.ruleIDs[abuse.BlockedPort] = options.BlockedPorts.RuleID
	guard.ruleIDs[abuse.PortScan] = options.PortScan.RuleID
	guard.ruleIDs[abuse.Flood] = options.Flood.RuleID
	guard.ruleIDs[abuse.BruteForce] = options.BruteForce.RuleID
	guard.ruleIDs[abuse.Exploit] = options.Exploits.RuleID
	guard.ruleIDs[abuse.Mining] = options.Mining.RuleID
	if !options.Exploits.Disabled || !options.Mining.Disabled {
		var err error
		guard.signatures, err = newSignatureSet(options.Signatures, !options.Exploits.Disabled, !options.Mining.Disabled)
		if err != nil {
			return nil, err
		}
	}
	return guard, nil
}

func orDefault[T comparable](value, fallback T) T {
	var zero T
	if value == zero {
		return fallback
	}
	return value
}

// abuseRefusal is an error that refuses a connection for abuse; the guard
// has logged it already.
type abuseRefusal struct{ error }

func (g *abuseGuard) refuse(message ...any) error {
	return abuseRefusal{E.New(message...)}
}

// admit runs the checks that need only the destination, before anything is
// read from the connection: the ban, and for TCP blocked ports and the counts
// that catch floods, port scans and brute force. A UDP session may send anywhere, so
// filterPackets checks each of its packets instead.
func (g *abuseGuard) admit(ctx context.Context, user *userState, network string, destination M.Socksaddr) error {
	now := time.Now()
	if user.abuse.Banned(now) {
		return g.refuse("banned on this node: ", destination)
	}
	if network != N.NetworkTCP {
		return nil
	}
	if slices.Contains(g.blockedPorts, destination.Port) {
		g.hit(ctx, user, abuse.BlockedPort, "", now, destination)
		return g.refuse("port ", destination.Port, " is blocked: ", destination)
	}
	verdict, crossed := user.abuse.Connect(&g.limits, now, destination)
	if !crossed && slices.Contains(g.loginPorts, destination.Port) {
		verdict, crossed = user.abuse.Login(&g.limits, now, destination)
	}
	if crossed {
		g.ban(ctx, user, verdict, now)
		return g.refuse("banned on this node: ", destination)
	}
	return nil
}

// inspectsPayload reports whether the guard needs the first payload.
func (g *abuseGuard) inspectsPayload() bool {
	return g.p2p || g.signatures != nil
}

// checkStream refuses a TCP connection whose first payload is P2P, an
// exploit attempt or a mining login.
func (g *abuseGuard) checkStream(ctx context.Context, user *userState, metadata *boxAdapter.InboundContext, payload []byte) error {
	if g.signatures != nil {
		if signature, found := abuse.MatchSignatures(g.signatures.current(), payload); found {
			g.hit(ctx, user, signature.Kind, signature.Name, time.Now(), metadata.Destination)
			return g.refuse(signature.Kind.String(), " (", signature.Name, ") refused: ", metadata.Destination)
		}
	}
	if !g.p2p {
		return nil
	}
	protocol, found := abuse.P2PStream(payload)
	if metadata.Protocol == C.ProtocolBitTorrent {
		protocol, found = abuse.BitTorrent, true
	}
	if !found {
		return nil
	}
	g.hit(ctx, user, abuse.P2P, protocol, time.Now(), metadata.Destination)
	return g.refuse(protocol, " refused: ", metadata.Destination)
}

// checkPacket refuses a UDP session whose first packet is P2P.
func (g *abuseGuard) checkPacket(ctx context.Context, user *userState, metadata *boxAdapter.InboundContext, payload []byte) error {
	if !g.p2p {
		return nil
	}
	protocol, found := abuse.P2PPacket(payload)
	if metadata.Protocol == C.ProtocolBitTorrent {
		protocol, found = abuse.BitTorrent, true
	}
	if !found {
		return nil
	}
	g.hit(ctx, user, abuse.P2P, protocol, time.Now(), metadata.Destination)
	return g.refuse(protocol, " refused: ", metadata.Destination)
}

// filterPackets drops the packets of a UDP session that go to a blocked port
// or are P2P, as a firewall would, so that the rest of the session carries
// on: a full-cone session sends each packet where it says, and a client may
// well open it with something else.
func (g *abuseGuard) filterPackets(ctx context.Context, user *userState, conn N.PacketConn) N.PacketConn {
	if !g.p2p && len(g.blockedPorts) == 0 {
		return conn
	}
	return &packetFilterConn{PacketConn: conn, ctx: ctx, guard: g, user: user}
}

// dropsPacket returns the kind of abuse a packet is, and for P2P the protocol.
func (g *abuseGuard) dropsPacket(destination M.Socksaddr, payload []byte) (abuse.Kind, string, bool) {
	if slices.Contains(g.blockedPorts, destination.Port) {
		return abuse.BlockedPort, "", true
	}
	if g.p2p {
		if protocol, found := abuse.P2PPacket(payload); found {
			return abuse.P2P, protocol, true
		}
	}
	return 0, "", false
}

// watchesDials reports whether failed dials count toward a port scan.
func (g *abuseGuard) watchesDials() bool {
	return g.limits.FailedDestinations > 0
}

// watchDial returns the dialer for one connection, which tells whether its
// dial got through.
func (g *abuseGuard) watchDial(dialer N.Dialer) *dialWatch {
	return &dialWatch{Dialer: dialer, guard: g, started: time.Now()}
}

// dialFailed counts a TCP connection the node could not open. Timeouts count:
// they are what a filtered port gives. What says more about the node than
// about the user does not: a dial canceled by the node shutting down, a
// network the node has no route to (IPv6 on a node without it), and any
// failure while nothing on the node gets through, as when its uplink or its
// front proxy is down. A node that is fine keeps reaching somewhere.
func (g *abuseGuard) dialFailed(ctx context.Context, user *userState, watch *dialWatch, destination M.Socksaddr, err error) {
	if errors.Is(err, context.Canceled) || localNetworkError(err) {
		return
	}
	if g.lastDial.Load() < watch.started.Add(-constant.AbuseOutageGrace).UnixNano() {
		return
	}
	now := time.Now()
	verdict, crossed := user.abuse.Fail(&g.limits, now, destination)
	if crossed {
		g.ban(ctx, user, verdict, now)
	}
}

func localNetworkError(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

func (g *abuseGuard) ban(ctx context.Context, user *userState, verdict abuse.Verdict, now time.Time) {
	user.abuse.Ban(now.Add(g.banDuration))
	user.closeConnections()
	g.logger.WarnContext(ctx, "[", user.id, "] banned on this node for ", g.banDuration.String(), ": ", verdict.Kind.String(), ", ", verdict.Reason)
	g.report(user, verdict.Kind)
}

// hit logs and reports a refused connection, unless the user had one of the
// same kind within AbuseNoticeInterval. protocol names what was found: the
// P2P protocol, or the signature.
func (g *abuseGuard) hit(ctx context.Context, user *userState, kind abuse.Kind, protocol string, now time.Time, destination M.Socksaddr) {
	if !user.abuse.Notice(kind, now, constant.AbuseNoticeInterval) {
		return
	}
	what := kind.String()
	if protocol != "" {
		what += " (" + protocol + ")"
	}
	g.logger.InfoContext(ctx, "[", user.id, "] ", what, " refused: ", destination, " (repeats within ", constant.AbuseNoticeInterval.String(), " are not logged)")
	g.report(user, kind)
}

func (g *abuseGuard) report(user *userState, kind abuse.Kind) {
	if ruleID := g.ruleIDs[kind]; ruleID > 0 {
		g.auditor.record(user.id, ruleID)
	}
}

// dialWatch tells whether a connection's dial got through, since the error
// its close handler gets may come from the dial or from the copy after it.
type dialWatch struct {
	N.Dialer
	guard     *abuseGuard
	started   time.Time
	connected atomic.Bool
}

func (d *dialWatch) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err == nil {
		d.connected.Store(true)
		d.guard.lastDial.Store(time.Now().UnixNano())
	}
	return conn, err
}

// packetFilterConn applies abuseGuard.filterPackets to what the client
// sends. Like the limiter, it exposes its upstream for type casts but is not
// replaceable, so copy loops cannot read around it.
type packetFilterConn struct {
	N.PacketConn
	ctx   context.Context
	guard *abuseGuard
	user  *userState
}

func (c *packetFilterConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	start := buffer.Start()
	for {
		destination, err := c.PacketConn.ReadPacket(buffer)
		if err != nil {
			return destination, err
		}
		kind, protocol, drop := c.guard.dropsPacket(destination, buffer.Bytes())
		if !drop {
			return destination, nil
		}
		c.guard.hit(c.ctx, c.user, kind, protocol, time.Now(), destination)
		buffer.Resize(start, 0)
	}
}

func (c *packetFilterConn) Upstream() any {
	return c.PacketConn
}
