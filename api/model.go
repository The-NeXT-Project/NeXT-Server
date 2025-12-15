package api

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

var (
	// ErrUserNotModified is returned when the user list is not modified.
	ErrUserNotModified = errors.New("users not modified")
	// ErrNodeNotEnabled is returned when the node is not enabled.
	ErrNodeNotEnabled = errors.New("node not enabled")
	// ErrNodeNotFound is returned when the node is not found.
	ErrNodeNotFound = errors.New("node not found")
	// ErrNodeOutOfBandwidth is returned when the node is out of bandwidth.
	ErrNodeOutOfBandwidth = errors.New("node out of bandwidth")
	// ErrNodeNotModified is returned when the node info is not modified.
	ErrNodeNotModified = errors.New("node not modified")
	// ErrRuleNotModified is returned when the rule list is not modified.
	ErrRuleNotModified = errors.New("rules not modified")
)

// Config API config
type Config struct {
	APIHost      string  `mapstructure:"ApiHost"`
	NodeID       int     `mapstructure:"NodeID"`
	Key          string  `mapstructure:"ApiKey"`
	NodeType     string  `mapstructure:"NodeType"`
	Timeout      int     `mapstructure:"Timeout"`
	SpeedLimit   float64 `mapstructure:"SpeedLimit"`
	DeviceLimit  int     `mapstructure:"DeviceLimit"`
	RuleListPath string  `mapstructure:"RuleListPath"`
}

type NodeInfo struct {
	NodeType          string // Must be vmess, trojan, shadowsocks and shadowsocks2022
	NodeID            int
	Port              uint32
	SpeedLimit        uint64 // Bps
	AlterID           uint16
	TransportProtocol string
	FakeType          string
	Host              string
	Path              string
	EnableTLS         bool
	CipherMethod      string
	ServerKey         string
	ServiceName       string
	Header            json.RawMessage
	NameServerConfig  []*conf.NameServerConfig
}

type UserInfo struct {
	UID         int
	Email       string
	UUID        string
	Passwd      string
	Port        uint32
	AlterID     uint16
	Method      string
	SpeedLimit  uint64 // Bps
	DeviceLimit int
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
	NodeType string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}
