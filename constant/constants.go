package constant

import "time"

const (
	DefaultPullInterval = 60 * time.Second
	DefaultPushInterval = 60 * time.Second
	// FinalPushTimeout bounds the traffic report sent while shutting down.
	FinalPushTimeout = 10 * time.Second
)

// Abuse check defaults (option.AbuseOptions).
const (
	DefaultAbuseBanDuration = 10 * time.Minute

	DefaultPortScanWindow             = time.Minute
	DefaultPortScanFailedDestinations = 60
	DefaultPortScanPortsPerHost       = 100

	DefaultFloodWindow                    = 10 * time.Second
	DefaultFloodConnections               = 1000
	DefaultFloodConnectionsPerDestination = 200

	// AbuseOutageGrace: a failed dial counts toward a port scan only if a
	// dial on the node got through since this long before it started.
	AbuseOutageGrace = 5 * time.Second

	// AbuseNoticeInterval is how often one user's repeated hits of one kind
	// are logged and reported to the panel.
	AbuseNoticeInterval = time.Minute
)

// DefaultBlockedPorts are refused unless configured otherwise: SMTP, which
// spam goes out on.
var DefaultBlockedPorts = []uint16{25}
