package controller

import (
	"encoding/json"
	"fmt"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	conf "github.com/v2fly/v2ray-core/v5/infra/conf/v4"

	"github.com/The-NeXT-Project/NeXT-Server/api"
)

// OutboundBuilder build freedom outbound config for addOutbound
func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// Build Send IP address
	if config.SendIP != "" {
		ipAddress := net.ParseAddress(config.SendIP)
		outboundDetourConfig.SendThrough = &cfgcommon.Address{Address: ipAddress}
	}

	// Freedom Protocol setting
	var domainStrategy = "Asis"

	if config.EnableDNS {
		if config.DNSType != "" {
			domainStrategy = config.DNSType
		} else {
			domainStrategy = "UseIP"
		}
	}

	proxySetting := &conf.FreedomConfig{
		DomainStrategy: domainStrategy,
	}

	var setting json.RawMessage

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}

	outboundDetourConfig.Settings = &setting

	return outboundDetourConfig.Build()
}
