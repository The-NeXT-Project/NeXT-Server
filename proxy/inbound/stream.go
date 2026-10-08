package inbound

import (
	"context"
	"net"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// StartStream serves a TCP based protocol: through transport when one is
// configured, which then owns TLS, or with a TLS handshake per connection.
func StartStream(
	l *Listener,
	logger logger.ContextLogger,
	tlsConfig tls.ServerConfig,
	transport boxAdapter.V2RayServerTransport,
	handler func(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext, onClose N.CloseHandlerFunc),
) error {
	if tlsConfig != nil {
		err := tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "start TLS")
		}
	}
	if transport == nil || common.Contains(transport.Network(), N.NetworkTCP) {
		tcpListener, err := l.ListenTCP()
		if err != nil {
			return err
		}
		if transport != nil {
			l.serve(func() error { return transport.Serve(tcpListener) }, logger)
		} else {
			l.ServeTCP(tcpListener, func(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext) {
				if tlsConfig != nil {
					tlsConn, err := tls.ServerHandshake(ctx, conn, tlsConfig)
					if err != nil {
						N.CloseOnHandshakeFailure(conn, nil, err)
						logger.DebugContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
						return
					}
					conn = tlsConn
				}
				handler(ctx, conn, metadata, nil)
			})
		}
	}
	if transport != nil && common.Contains(transport.Network(), N.NetworkUDP) {
		udpConn, err := l.ListenUDP()
		if err != nil {
			return err
		}
		l.serve(func() error { return transport.ServePacket(udpConn) }, logger)
	}
	return nil
}

func (l *Listener) serve(serve func() error, logger logger.ContextLogger) {
	l.serving.Add(1)
	go func() {
		defer l.serving.Done()
		err := serve()
		if err != nil && !E.IsClosed(err) {
			logger.Error("transport serve error: ", err)
		}
	}()
}

// CloseStream closes the sockets, then the transport once nothing serves it
// any more. sing-box's QUIC transport sets its listener up inside
// ServePacket, so closing it earlier races with that.
func (l *Listener) CloseStream(transport boxAdapter.V2RayServerTransport) error {
	err := l.Close()
	l.serving.Wait()
	if transport != nil {
		err = E.Errors(err, transport.Close())
	}
	return err
}
