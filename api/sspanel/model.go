package sspanel

import "encoding/json"

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	SpeedLimit      float64         `json:"node_speedlimit"`
	Sort            int             `json:"sort"`
	RawServerString string          `json:"server"`
	CustomConfig    json.RawMessage `json:"custom_config"`
	Type            string          `json:"type"`
	Version         string          `json:"version"`
}

type CustomConfig struct {
	OffsetPortNode string          `json:"offset_port_node"`
	Host           string          `json:"host"`
	Method         string          `json:"method"`
	TLS            string          `json:"tls"`
	Network        string          `json:"network"`
	Security       string          `json:"security"`
	Path           string          `json:"path"`
	VerifyCert     bool            `json:"verify_cert"`
	Header         json.RawMessage `json:"header"`
	AllowInsecure  string          `json:"allow_insecure"`
	ServerKey      string          `json:"server_key"`
	ServiceName    string          `json:"servicename"`
}

// UserResponse is the response of user
type UserResponse struct {
	ID         int     `json:"id"`
	Passwd     string  `json:"passwd"`
	Port       uint32  `json:"port"`
	Method     string  `json:"method"`
	SpeedLimit float64 `json:"node_speedlimit"`
	UUID       string  `json:"uuid"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
	Msg  string          `json:"msg"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	UID int    `json:"user_id"`
	IP  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type UserTraffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type RuleItem struct {
	ID      int    `json:"id"`
	Content string `json:"regex"`
}

type IllegalItem struct {
	ID  int `json:"list_id"`
	UID int `json:"user_id"`
}
