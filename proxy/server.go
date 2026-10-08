package proxy

import (
	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/anytls"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/hysteria2"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/shadowsocks"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/trojan"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/tuic"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/vmess"

	E "github.com/sagernet/sing/common/exceptions"
)

func New(options inbound.NodeOptions) (adapter.NodeServer, error) {
	switch options.Config.Type {
	case adapter.NodeTypeShadowsocks2022:
		return shadowsocks.New(options)
	case adapter.NodeTypeTUIC:
		return tuic.New(options)
	case adapter.NodeTypeHysteria2:
		return hysteria2.New(options)
	case adapter.NodeTypeAnyTLS:
		return anytls.New(options)
	case adapter.NodeTypeVMess:
		return vmess.New(options)
	case adapter.NodeTypeTrojan:
		return trojan.New(options)
	default:
		return nil, E.New("unsupported node type: ", options.Config.Type)
	}
}
