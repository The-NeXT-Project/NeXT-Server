package controller

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/The-NeXT-Project/NeXT-Server/api"
)

// OutboundBuilder build freedom outbound config for addOutbound
func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// Build Send IP address
	if config.SendIP != "" {
		ipAddress := net.ParseAddress(config.SendIP).String()
		outboundDetourConfig.SendThrough = &ipAddress
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
