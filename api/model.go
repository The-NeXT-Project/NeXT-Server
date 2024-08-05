package api

import (
	"encoding/json"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

const (
	UserNotModified = "users not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
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
