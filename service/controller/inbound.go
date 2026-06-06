// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/sniffer"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/socketcfg"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"
	conf "github.com/v2fly/v2ray-core/v5/infra/conf/v4"

	"github.com/The-NeXT-Project/NeXT-Server/api"
	"github.com/The-NeXT-Project/NeXT-Server/common/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &cfgcommon.Address{Address: ipAddress}
	}
	// Build Port
	inboundDetourConfig.PortRange = &cfgcommon.PortRange{
		From: nodeInfo.Port,
		To:   nodeInfo.Port,
	}
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &sniffer.SniffingConfig{
		Enabled:      true,
		DestOverride: &cfgcommon.StringList{"http", "tls"},
	}

	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}

	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
		proxySetting  any
	)
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "vmess":
		protocol = "vmess"
		proxySetting = map[string]any{}
	case "trojan":
		protocol = "trojan"
		proxySetting = map[string]any{}
	case "shadowsocks":
		protocol = "shadowsocks"
		ssSetting := &conf.ShadowsocksServerConfig{}
		// shadowsocks must have a random password
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		ssSetting.Password = hex.EncodeToString(b)
		ssSetting.NetworkList = &cfgcommon.NetworkList{"tcp", "udp"}
		ssSetting.IVCheck = !config.DisableIVCheck

		proxySetting = ssSetting
	case "shadowsocks2022":
		return nil, fmt.Errorf("shadowsocks2022 inbound is not supported by v2ray-core v5")
	default:
		return nil, fmt.Errorf("unsupported node type:"+
			" %s, Only support: vmess, trojan, and shadowsocks", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}

	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting
	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)

	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	hosts := cfgcommon.StringList{nodeInfo.Host}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}

		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host

		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}

		streamSetting.WSSettings = wsSettings
	case "http":
		httpSettings := &conf.HTTPConfig{
			Host: &hosts,
			Path: nodeInfo.Path,
		}

		streamSetting.HTTPSettings = httpSettings
	case "httpupgrade":
		httpSettings := &conf.HTTPConfig{
			Host: &hosts,
			Path: nodeInfo.Path,
		}

		streamSetting.HTTPSettings = httpSettings
	case "splithttp":
		return nil, fmt.Errorf("splithttp transport is not supported by v2ray-core v5")
	case "grpc":
		grpcSettings := &conf.GunConfig{
			ServiceName: nodeInfo.ServiceName,
		}

		streamSetting.GRPCSettings = grpcSettings
	case "quic":
		quicSettings := &conf.QUICConfig{
			Security: "none",
		}

		streamSetting.QUICSettings = quicSettings
	case "kcp":
		mtu := uint32(1350)
		upCap := uint32(100)
		downCap := uint32(100)
		congestion := true

		kcpSettings := &conf.KCPConfig{
			Mtu:        &mtu,
			UpCap:      &upCap,
			DownCap:    &downCap,
			Congestion: &congestion,
		}

		streamSetting.KCPSettings = kcpSettings
	}

	streamSetting.Network = &transportProtocol

	if nodeInfo.EnableTLS && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"

		certFile, keyFile, err := getCertFile(config.CertConfig)
		if err != nil {
			return nil, err
		}

		tlsSettings := &tlscfg.TLSConfig{}

		tlsSettings.Certs = append(tlsSettings.Certs, &tlscfg.TLSCertConfig{CertFile: certFile, KeyFile: keyFile})
		streamSetting.TLSSettings = tlsSettings
	}
	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && config.EnableProxyProtocol {
		sockoptConfig := &socketcfg.SocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
		}

		streamSetting.SocketSettings = sockoptConfig
	}

	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig) (certFile string, keyFile string, err error) {
	switch certConfig.CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}

		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}

		certPath, keyPath, err := lego.DNSCert()
		if err != nil {
			return "", "", err
		}

		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}

		certPath, keyPath, err := lego.HTTPCert()
		if err != nil {
			return "", "", err
		}

		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}
