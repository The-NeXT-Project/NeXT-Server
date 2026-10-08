package serverv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"

	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	defaultPort              = 443
	defaultSS2022Method      = "2022-blake3-aes-128-gcm"
	defaultCongestionControl = "bbr"
	defaultObfsType          = "salamander"
)

type nodeInfo struct {
	SpeedLimit   Number          `json:"node_speedlimit"`
	Sort         int             `json:"sort"`
	Server       string          `json:"server"`
	CustomConfig json.RawMessage `json:"custom_config"`
}

// customConfig holds the node fields the server side reads. Admins type
// custom_config by hand, so numbers may arrive as strings.
type customConfig struct {
	OffsetPortNode Number `json:"offset_port_node"`
	OffsetPortUser Number `json:"offset_port_user"`
	Host           string `json:"host"`

	Method    string `json:"method"`
	ServerKey string `json:"server_key"`

	Network     string `json:"network"`
	Security    string `json:"security"`
	Path        string `json:"path"`
	ServiceName string `json:"servicename"`
	Header      struct {
		Request struct {
			Path    []string            `json:"path"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
	} `json:"header"`

	CongestionControl string `json:"congestion_control"`

	Obfs         string `json:"obfs"`
	ObfsPassword string `json:"obfs_password"`

	PaddingScheme []string `json:"padding_scheme"`
}

func (c *Client) FetchNodeConfig(ctx context.Context) (*adapter.NodeConfig, error) {
	var info nodeInfo
	modified, err := c.get(ctx, "/info", &c.infoETag, &info)
	if err != nil || !modified {
		return nil, err
	}
	config, err := c.parseNodeConfig(info)
	if err != nil {
		// Without this the next poll would get a 304 and keep the broken config silently.
		c.infoETag = ""
		return nil, err
	}
	return config, nil
}

func (c *Client) parseNodeConfig(info nodeInfo) (*adapter.NodeConfig, error) {
	var custom customConfig
	// An empty PHP array encodes as [], not {}.
	if trimmed := bytes.TrimSpace(info.CustomConfig); len(trimmed) > 0 && trimmed[0] == '{' {
		err := json.Unmarshal(trimmed, &custom)
		if err != nil {
			return nil, E.Cause(err, "decode custom_config")
		}
	}
	nodeType := adapter.NodeType(info.Sort)
	config := &adapter.NodeConfig{
		Type:       nodeType,
		SpeedLimit: mbpsToBytes(float64(info.SpeedLimit)),
	}
	port := firstPositive(int64(custom.OffsetPortNode), int64(custom.OffsetPortUser), defaultPort)
	if port > 65535 {
		return nil, E.New("invalid port: ", port)
	}
	config.ListenPort = uint16(port)

	serverName := custom.Host
	if serverName == "" && M.IsDomainName(info.Server) {
		serverName = info.Server
	}
	var err error
	switch nodeType {
	case adapter.NodeTypeShadowsocks2022:
		config.Shadowsocks.Method = custom.Method
		if config.Shadowsocks.Method == "" {
			config.Shadowsocks.Method = defaultSS2022Method
		}
		// Without a server key a client's password is its user key alone, and
		// the server cannot tell which user a connection belongs to.
		if custom.ServerKey == "" {
			return nil, E.New("shadowsocks 2022: custom_config.server_key is required for a multi-user node")
		}
		config.Shadowsocks.ServerKey = custom.ServerKey
	case adapter.NodeTypeTUIC:
		config.TLS, err = c.buildTLS(serverName, []string{"h3"})
		config.TUIC.CongestionControl = custom.CongestionControl
		if config.TUIC.CongestionControl == "" {
			config.TUIC.CongestionControl = defaultCongestionControl
		}
	case adapter.NodeTypeHysteria2:
		config.TLS, err = c.buildTLS(serverName, nil)
		// up_mbps and down_mbps describe the client's link; the server takes
		// what each client declares.
		if custom.ObfsPassword != "" {
			config.Hysteria2.ObfsType = custom.Obfs
			if config.Hysteria2.ObfsType == "" {
				config.Hysteria2.ObfsType = defaultObfsType
			}
			config.Hysteria2.ObfsPassword = custom.ObfsPassword
		}
	case adapter.NodeTypeAnyTLS:
		config.TLS, err = c.buildTLS(serverName, nil)
		config.AnyTLS.PaddingScheme = custom.PaddingScheme
	case adapter.NodeTypeVMess:
		if custom.Security == "tls" {
			config.TLS, err = c.buildTLS(serverName, nil)
		}
		config.Transport = buildTransport(custom)
	case adapter.NodeTypeTrojan:
		config.TLS, err = c.buildTLS(serverName, nil)
		config.Transport = buildTransport(custom)
	default:
		return nil, E.New("unsupported node type: ", nodeType)
	}
	if err != nil {
		return nil, err
	}
	return config, nil
}

// buildTLS merges the local certificate source with what the panel knows
// about the node.
func (c *Client) buildTLS(serverName string, alpn []string) (*boxOption.InboundTLSOptions, error) {
	var options boxOption.InboundTLSOptions
	if c.localTLS != nil {
		options = *c.localTLS
	}
	options.Enabled = true
	if options.ServerName == "" {
		options.ServerName = serverName
	}
	if len(options.ALPN) == 0 {
		options.ALPN = alpn
	}
	//nolint:staticcheck
	if options.ACME != nil && len(options.ACME.Domain) == 0 {
		if serverName == "" {
			return nil, E.New("tls: acme needs a domain, set custom_config.host or a domain node address")
		}
		acmeOptions := *options.ACME
		acmeOptions.Domain = []string{serverName}
		options.ACME = &acmeOptions
	}
	//nolint:staticcheck
	hasCertificate := len(options.Certificate) > 0 || options.CertificatePath != "" ||
		options.ACME != nil || options.CertificateProvider != nil || options.Reality != nil
	if !hasCertificate {
		// sing-box generates a self-signed certificate per server name.
		options.Insecure = true
	}
	return &options, nil
}

func buildTransport(custom customConfig) *boxOption.V2RayTransportOptions {
	host := custom.Host
	if hosts := custom.Header.Request.Headers["Host"]; len(hosts) > 0 {
		host = hosts[0]
	}
	path := custom.Path
	if len(custom.Header.Request.Path) > 0 {
		path = custom.Header.Request.Path[0]
	}
	var transport boxOption.V2RayTransportOptions
	switch custom.Network {
	case "ws":
		transport.Type = C.V2RayTransportTypeWebsocket
		transport.WebsocketOptions.Path = path
	case "http", "h2":
		transport.Type = C.V2RayTransportTypeHTTP
		transport.HTTPOptions.Path = path
		if host != "" {
			transport.HTTPOptions.Host = []string{host}
		}
	case "httpupgrade":
		transport.Type = C.V2RayTransportTypeHTTPUpgrade
		transport.HTTPUpgradeOptions.Path = path
		transport.HTTPUpgradeOptions.Host = host
	case "grpc":
		transport.Type = C.V2RayTransportTypeGRPC
		transport.GRPCOptions.ServiceName = custom.ServiceName
	case "quic":
		transport.Type = C.V2RayTransportTypeQUIC
	default:
		// Plain TCP, or a network sing-box has no name for, which the
		// panel also leaves out of client profiles.
		return nil
	}
	return &transport
}

type user struct {
	ID         int    `json:"id"`
	SpeedLimit Number `json:"node_speedlimit"`
	Password   string `json:"passwd"`
	UUID       string `json:"uuid"`
}

func (c *Client) FetchUsers(ctx context.Context) ([]adapter.User, error) {
	var users []user
	modified, err := c.get(ctx, "/users", &c.usersETag, &users)
	if err != nil {
		var apiErr *Error
		if errors.As(err, &apiErr) && (apiErr.Code == "out_of_bandwidth" || apiErr.Code == "node_disabled") {
			// The next answer must be applied even if it is identical to the
			// last list we served.
			c.usersETag = ""
			return nil, E.Cause(ErrNodeUnavailable, apiErr.Code)
		}
		return nil, err
	}
	if !modified {
		return nil, nil
	}
	result := make([]adapter.User, 0, len(users))
	for _, it := range users {
		if it.ID <= 0 {
			continue
		}
		result = append(result, adapter.User{
			ID:         it.ID,
			UUID:       it.UUID,
			Password:   it.Password,
			SpeedLimit: mbpsToBytes(float64(it.SpeedLimit)),
		})
	}
	return result, nil
}

type detectRule struct {
	ID    int    `json:"id"`
	Regex string `json:"regex"`
	Type  int    `json:"type"`
}

func (c *Client) FetchDetectRules(ctx context.Context) ([]adapter.DetectRule, error) {
	var rules []detectRule
	modified, err := c.get(ctx, "/detect_rules", &c.rulesETag, &rules)
	if err != nil || !modified {
		return nil, err
	}
	result := make([]adapter.DetectRule, 0, len(rules))
	var errs []error
	for _, it := range rules {
		pattern, err := regexp.Compile(it.Regex)
		if err != nil {
			errs = append(errs, E.Cause(err, "detect rule ", it.ID))
			continue
		}
		result = append(result, adapter.DetectRule{
			ID:     it.ID,
			Type:   adapter.DetectRuleType(it.Type),
			Regexp: pattern,
		})
	}
	// Invalid rules are reported but do not keep the valid ones from applying.
	return result, E.Errors(errs...)
}

func mbpsToBytes(mbps float64) uint64 {
	if mbps <= 0 {
		return 0
	}
	return uint64(mbps * 1_000_000 / 8)
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
