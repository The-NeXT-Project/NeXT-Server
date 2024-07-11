package controller

import (
	"github.com/The-NeXT-Project/NeXT-Server/common/mylego"
)

type Config struct {
	ListenIP             string                `mapstructure:"ListenIP"`
	SendIP               string                `mapstructure:"SendIP"`
	UpdatePeriodic       int                   `mapstructure:"UpdatePeriodic"`
	CertConfig           *mylego.CertConfig    `mapstructure:"CertConfig"`
	EnableDNS            bool                  `mapstructure:"EnableDNS"`
	DNSType              string                `mapstructure:"DNSType"`
	DisableUploadTraffic bool                  `mapstructure:"DisableUploadTraffic"`
	DisableGetRule       bool                  `mapstructure:"DisableGetRule"`
	EnableProxyProtocol  bool                  `mapstructure:"EnableProxyProtocol"`
	DisableIVCheck       bool                  `mapstructure:"DisableIVCheck"`
	DisableSniffing      bool                  `mapstructure:"DisableSniffing"`
	AutoSpeedLimitConfig *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimitConfig"`
}

type AutoSpeedLimitConfig struct {
	Limit         int `mapstructure:"Limit"` // mbps
	WarnTimes     int `mapstructure:"WarnTimes"`
	LimitSpeed    int `mapstructure:"LimitSpeed"`    // mbps
	LimitDuration int `mapstructure:"LimitDuration"` // minute
}
