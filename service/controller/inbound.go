// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/The-NeXT-Project/NeXT-Server/api"
	"github.com/The-NeXT-Project/NeXT-Server/common/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}
	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}

	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls"},
		RouteOnly:    true,
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
		proxySetting = &conf.VMessInboundConfig{}
	case "trojan":
		protocol = "trojan"
		proxySetting = &conf.TrojanServerConfig{}
	case "shadowsocks":
		protocol = "shadowsocks"
		ssSetting := &conf.ShadowsocksServerConfig{}
		// shadowsocks must have a random password
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		ssSetting.Password = hex.EncodeToString(b)
		ssSetting.NetworkList = &conf.NetworkList{"tcp", "udp"}
		ssSetting.IVCheck = !config.DisableIVCheck

		proxySetting = ssSetting
	case "shadowsocks2022":
		protocol = "shadowsocks"
		ss2022Setting := &conf.ShadowsocksServerConfig{}
		ss2022Setting.Cipher = strings.ToLower(nodeInfo.CipherMethod)
		ss2022Setting.Password = nodeInfo.ServerKey // shadowsocks2022 shareKey
		// shadowsocks2022's password == user PSK, thus should a length of string >= 32 and base64 encoder
		b := make([]byte, 32)
		_, _ = rand.Read(b)

		ss2022Setting.Users = append(ss2022Setting.Users, &conf.ShadowsocksUserConfig{
			Password: base64.StdEncoding.EncodeToString(b),
		})

		ss2022Setting.NetworkList = &conf.NetworkList{"tcp", "udp"}
		ss2022Setting.IVCheck = !config.DisableIVCheck

		proxySetting = ss2022Setting
	default:
		return nil, fmt.Errorf("unsupported node type:"+
			" %s, Only support: vmess, trojan, shadowsocks and shadowsocks2022", nodeInfo.NodeType)
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

	hosts := conf.StringList{nodeInfo.Host}

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
		var headers map[string]string
		_ = json.Unmarshal(nodeInfo.Header, &headers)

		splitHttpSettings := &conf.SplitHTTPConfig{
			Host:    nodeInfo.Host,
			Path:    nodeInfo.Path,
			Headers: headers,
		}

		streamSetting.SplitHTTPSettings = splitHttpSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
		}

		streamSetting.GRPCConfig = grpcSettings
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

		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}

		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}
	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && config.EnableProxyProtocol {
		sockoptConfig := &conf.SocketConfig{
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
