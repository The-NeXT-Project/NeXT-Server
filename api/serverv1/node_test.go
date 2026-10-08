package serverv1

import (
	"encoding/json"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"

	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

func parse(t *testing.T, client *Client, info string) (*adapter.NodeConfig, error) {
	t.Helper()
	var decoded nodeInfo
	if err := json.Unmarshal([]byte(info), &decoded); err != nil {
		t.Fatal(err)
	}
	return client.parseNodeConfig(decoded)
}

func TestParseNodeConfig(t *testing.T) {
	client := &Client{}
	t.Run("string ports and port precedence", func(t *testing.T) {
		config, err := parse(t, client, `{"sort":11,"node_speedlimit":"8","server":"1.2.3.4","custom_config":{"offset_port_node":"","offset_port_user":"8443"}}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.ListenPort != 8443 {
			t.Error("listen port ", config.ListenPort, ", want offset_port_user when offset_port_node is empty")
		}
		if config.SpeedLimit != 1_000_000 {
			t.Error("speed limit ", config.SpeedLimit, ", want 8 Mbps in bytes")
		}
		if config.TLS != nil || config.Transport != nil {
			t.Error("plain vmess got TLS or a transport")
		}
	})
	t.Run("empty custom_config array", func(t *testing.T) {
		config, err := parse(t, client, `{"sort":14,"server":"node.example.com","custom_config":[]}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.ListenPort != 443 || config.TLS == nil || config.TLS.ServerName != "node.example.com" || !config.TLS.Insecure {
			t.Errorf("unexpected trojan defaults: %+v %+v", config, config.TLS)
		}
	})
	t.Run("vmess transport from header", func(t *testing.T) {
		config, err := parse(t, client, `{"sort":11,"server":"1.2.3.4","custom_config":{"offset_port_node":80,"network":"h2","security":"tls","host":"a.example","path":"/a",
			"header":{"type":"http","request":{"path":["/b"],"headers":{"Host":["b.example"]}}}}}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.TLS == nil || config.TLS.ServerName != "a.example" {
			t.Errorf("tls: %+v", config.TLS)
		}
		transport := config.Transport
		if transport == nil || transport.Type != C.V2RayTransportTypeHTTP || transport.HTTPOptions.Path != "/b" ||
			len(transport.HTTPOptions.Host) != 1 || transport.HTTPOptions.Host[0] != "b.example" {
			t.Errorf("transport: %+v", transport)
		}
	})
	t.Run("unknown network is plain tcp", func(t *testing.T) {
		config, err := parse(t, client, `{"sort":14,"server":"1.2.3.4","custom_config":{"network":"kcp"}}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.Transport != nil {
			t.Errorf("transport: %+v", config.Transport)
		}
	})
	t.Run("shadowsocks 2022 needs a server key", func(t *testing.T) {
		if _, err := parse(t, client, `{"sort":1,"server":"1.2.3.4","custom_config":{"method":"2022-blake3-aes-256-gcm"}}`); err == nil {
			t.Error("accepted a node without server_key")
		}
		config, err := parse(t, client, `{"sort":1,"server":"1.2.3.4","custom_config":{"server_key":"key"}}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.Shadowsocks.Method != defaultSS2022Method {
			t.Error("method ", config.Shadowsocks.Method)
		}
	})
	t.Run("hysteria2 obfs", func(t *testing.T) {
		config, err := parse(t, client, `{"sort":4,"server":"1.2.3.4","custom_config":{"obfs_password":"secret"}}`)
		if err != nil {
			t.Fatal(err)
		}
		if config.Hysteria2.ObfsType != "salamander" || config.Hysteria2.ObfsPassword != "secret" {
			t.Errorf("%+v", config.Hysteria2)
		}
	})
	t.Run("unsupported types", func(t *testing.T) {
		for _, sort := range []string{"3", "6", "0", "99"} {
			if _, err := parse(t, client, `{"sort":`+sort+`,"custom_config":{}}`); err == nil {
				t.Error("sort ", sort, " accepted")
			}
		}
	})
}

func TestBuildTLS(t *testing.T) {
	t.Run("acme takes the node host", func(t *testing.T) {
		local := &boxOption.InboundTLSOptions{
			//nolint:staticcheck
			ACME: &boxOption.InboundACMEOptions{Email: "admin@example.com"},
		}
		client := &Client{localTLS: local}
		options, err := client.buildTLS("node.example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		//nolint:staticcheck
		if options.Insecure || len(options.ACME.Domain) != 1 || options.ACME.Domain[0] != "node.example.com" {
			t.Errorf("%+v", options)
		}
		//nolint:staticcheck
		if len(local.ACME.Domain) != 0 {
			t.Error("the local options were modified")
		}
		if _, err = client.buildTLS("", nil); err == nil {
			t.Error("acme without a domain was accepted")
		}
	})
	t.Run("certificate file is kept", func(t *testing.T) {
		client := &Client{localTLS: &boxOption.InboundTLSOptions{CertificatePath: "c.pem", KeyPath: "k.pem", ServerName: "fixed.example"}}
		options, err := client.buildTLS("node.example.com", []string{"h3"})
		if err != nil {
			t.Fatal(err)
		}
		if options.Insecure || options.ServerName != "fixed.example" || options.ALPN[0] != "h3" || !options.Enabled {
			t.Errorf("%+v", options)
		}
	})
}

func TestNumber(t *testing.T) {
	for input, want := range map[string]Number{`""`: 0, `null`: 0, `"12"`: 12, `12`: 12, `"1.5"`: 1.5, `" 7 "`: 7} {
		var number Number
		if err := json.Unmarshal([]byte(input), &number); err != nil || number != want {
			t.Errorf("%s: got %v, %v", input, number, err)
		}
	}
	var number Number
	if err := json.Unmarshal([]byte(`"abc"`), &number); err == nil {
		t.Error("accepted a non-numeric string")
	}
}
