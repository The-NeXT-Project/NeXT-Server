package option

import "github.com/sagernet/sing/common/json/badoption"

// AbuseOptions configures the node's own abuse checks, which run whether or
// not the panel has detect rules. Every check is on by default.
type AbuseOptions struct {
	// Disabled turns every check off.
	Disabled bool `json:"disabled,omitempty"`
	// BanDuration is how long a user caught scanning or flooding is refused
	// on this node, 10 minutes by default.
	BanDuration badoption.Duration `json:"ban_duration,omitempty"`

	BitTorrent   AbuseCheckOptions        `json:"bittorrent,omitempty"`
	BlockedPorts AbuseBlockedPortsOptions `json:"blocked_ports,omitempty"`
	PortScan     AbusePortScanOptions     `json:"port_scan,omitempty"`
	Flood        AbuseFloodOptions        `json:"flood,omitempty"`
}

type AbuseCheckOptions struct {
	Disabled bool `json:"disabled,omitempty"`
	// RuleID reports hits to the panel as hits of this detect rule, so that
	// they show in its detect log and count toward its automatic ban. 0
	// reports nothing.
	RuleID int `json:"rule_id,omitempty"`
}

type AbuseBlockedPortsOptions struct {
	AbuseCheckOptions
	// Ports are refused for TCP and UDP. Left out, it is [25] (SMTP, which
	// spam goes out on); an empty list refuses nothing.
	Ports []uint16 `json:"ports,omitempty"`
}

// AbusePortScanOptions bans a user whose TCP connections fail for too many
// destinations, or reach too many ports of one host, within a window.
type AbusePortScanOptions struct {
	AbuseCheckOptions
	Window             badoption.Duration `json:"window,omitempty"`
	FailedDestinations int                `json:"failed_destinations,omitempty"`
	PortsPerHost       int                `json:"ports_per_host,omitempty"`
}

// AbuseFloodOptions bans a user who opens too many TCP connections, in
// total or to one destination, within a window.
type AbuseFloodOptions struct {
	AbuseCheckOptions
	Window                    badoption.Duration `json:"window,omitempty"`
	Connections               int                `json:"connections,omitempty"`
	ConnectionsPerDestination int                `json:"connections_per_destination,omitempty"`
}
