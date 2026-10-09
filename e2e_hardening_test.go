package nextserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	boxOption "github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// refusedTCP fails the test if destination answers through dialer.
func refusedTCP(t *testing.T, dialer N.Dialer, destination M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	go conn.Write([]byte("ping"))
	if _, err = io.ReadFull(conn, make([]byte, 4)); err == nil {
		t.Fatal("reached ", destination)
	}
}

func refusedUDP(t *testing.T, dialer N.Dialer, destination M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		return
	}
	defer conn.Close()
	for attempt := 0; attempt < 3; attempt++ {
		conn.WriteTo([]byte("ping"), destination.UDPAddr())
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err = conn.ReadFrom(make([]byte, 64)); err == nil {
			t.Fatal("reached ", destination)
		}
	}
}

func TestPrivateDestinationsRefused(t *testing.T) {
	tcpEcho, udpEcho := startEcho(t)
	port := freePort(t)
	_, panelServer := newFakePanel(t, 14, map[string]any{"offset_port_node": port, "host": "node.example.com"}, testUsers())
	startNextServer(t, panelServer.URL, func(options *option.ServerOptions) {
		options.AllowPrivateDestinations = false
	})
	dialer := startClient(t, map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": port, "password": userUUID, "tls": insecureTLS()})

	refusedTCP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(tcpEcho)))
	// Resolved by the server, to loopback.
	refusedTCP(t, dialer, M.ParseSocksaddrHostPort("localhost", uint16(tcpEcho)))
	refusedUDP(t, dialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(udpEcho)))
}

// seedACMECertificate stores a certificate for domain where certmagic keeps
// Let's Encrypt's, so that the server starts with it instead of issuing one.
func seedACMECertificate(t *testing.T, dataDirectory string, domain string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(dataDirectory, "certificates", "acme-v02.api.letsencrypt.org-directory", domain)
	if err = os.MkdirAll(site, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		domain + ".crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
		domain + ".key":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}),
		domain + ".json": []byte(`{"sans":["` + domain + `"]}`),
	}
	for name, content := range files {
		if err = os.WriteFile(filepath.Join(site, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A CDN in front of a node asks for its own name, which the node's ACME
// certificate does not cover; the node must still serve it.
func TestACMECertificateForOtherNames(t *testing.T) {
	if !slices.Contains(constant.BuildTags(), "with_acme") {
		t.Skip("built without with_acme")
	}
	for _, network := range []string{"tcp", "ws"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()
			dataDirectory := t.TempDir()
			seedACMECertificate(t, dataDirectory, "node.example.com")
			port := freePort(t)
			// The panel's address is the CDN's name, as for a CloudFront node.
			panel, panelServer := newFakePanel(t, 14, map[string]any{"offset_port_node": port, "network": network, "path": "/ws"}, testUsers())
			panel.update(func(p *fakePanel) { p.info["server"] = "cdn.example.net" })
			startNextServer(t, panelServer.URL, func(options *option.ServerOptions) {
				options.TLS = &boxOption.InboundTLSOptions{ACME: &boxOption.InboundACMEOptions{
					Domain:                  []string{"node.example.com"},
					DataDirectory:           dataDirectory,
					Email:                   "admin@example.com",
					DisableHTTPChallenge:    true,
					DisableTLSALPNChallenge: true,
				}}
			})
			for _, serverName := range []string{"node.example.com", "cdn.example.net", ""} {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
					&tls.Config{ServerName: serverName, InsecureSkipVerify: true})
				if err != nil {
					t.Fatalf("handshake for %q: %v", serverName, err)
				}
				served := conn.ConnectionState().PeerCertificates[0].DNSNames
				conn.Close()
				if !slices.Equal(served, []string{"node.example.com"}) {
					t.Errorf("served %v for %q", served, serverName)
				}
			}
		})
	}
}
