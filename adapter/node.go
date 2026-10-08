package adapter

import (
	"context"
	"regexp"

	boxOption "github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
)

// NodeType is the panel's node `sort`.
type NodeType int

const (
	NodeTypeShadowsocks2022 NodeType = 1
	NodeTypeTUIC            NodeType = 2
	NodeTypeSnell           NodeType = 3
	NodeTypeHysteria2       NodeType = 4
	NodeTypeAnyTLS          NodeType = 5
	NodeTypeNaive           NodeType = 6
	NodeTypeVMess           NodeType = 11
	NodeTypeTrojan          NodeType = 14
)

var nameByNodeType = map[NodeType]string{
	NodeTypeShadowsocks2022: "shadowsocks2022",
	NodeTypeTUIC:            "tuic",
	NodeTypeSnell:           "snell",
	NodeTypeHysteria2:       "hysteria2",
	NodeTypeAnyTLS:          "anytls",
	NodeTypeNaive:           "naive",
	NodeTypeVMess:           "vmess",
	NodeTypeTrojan:          "trojan",
}

func (t NodeType) String() string {
	if name, loaded := nameByNodeType[t]; loaded {
		return name
	}
	return "sort(" + F.ToString(int(t)) + ")"
}

// NodeConfig is everything a node server needs to listen, decoded from the
// panel's node info and merged with the local server options. Two configs that
// compare equal with reflect.DeepEqual produce the same listener, so the server
// only restarts when this changes.
type NodeConfig struct {
	Type       NodeType
	ListenPort uint16
	// SpeedLimit is the node-wide per-user limit in bytes per second, 0 for none.
	SpeedLimit uint64

	// TLS is nil for protocols or node settings without TLS.
	TLS *boxOption.InboundTLSOptions
	// Transport is nil for plain TCP.
	Transport *boxOption.V2RayTransportOptions

	Shadowsocks ShadowsocksConfig
	TUIC        TUICConfig
	Hysteria2   Hysteria2Config
	AnyTLS      AnyTLSConfig
}

type ShadowsocksConfig struct {
	Method    string
	ServerKey string
}

type TUICConfig struct {
	CongestionControl string
}

type Hysteria2Config struct {
	ObfsType     string
	ObfsPassword string
}

type AnyTLSConfig struct {
	PaddingScheme []string
}

// User is a panel account allowed on this node. Which credential a protocol
// reads depends on the node type: VMess and Trojan authenticate with UUID,
// TUIC with UUID and Password, everything else with Password.
type User struct {
	ID       int
	UUID     string
	Password string
	// SpeedLimit is in bytes per second, 0 for none.
	SpeedLimit uint64
}

// DetectRuleType selects what a detect rule's regex is matched against.
type DetectRuleType int

const (
	// DetectRuleTypePlain matches the destination host, the sniffed domain
	// and the first payload of the connection as text.
	DetectRuleTypePlain DetectRuleType = 1
	// DetectRuleTypeHex matches the hex encoding of the first payload.
	DetectRuleTypeHex DetectRuleType = 2
)

type DetectRule struct {
	ID     int
	Type   DetectRuleType
	Regexp *regexp.Regexp
}

type UserTraffic struct {
	UserID   int
	Upload   int64
	Download int64
}

type UserOnline struct {
	UserID int
	IP     string
}

type DetectLog struct {
	UserID int
	RuleID int
}

// APIClient talks to the panel. The Fetch methods return (nil, nil) when the
// resource is unchanged since the last successful fetch.
type APIClient interface {
	FetchNodeConfig(ctx context.Context) (*NodeConfig, error)
	FetchUsers(ctx context.Context) ([]User, error)
	FetchDetectRules(ctx context.Context) ([]DetectRule, error)
	Heartbeat(ctx context.Context, onlineUsers int) error
	ReportTraffic(ctx context.Context, items []UserTraffic) error
	ReportOnline(ctx context.Context, items []UserOnline) error
	ReportDetectLogs(ctx context.Context, items []DetectLog) error
}
