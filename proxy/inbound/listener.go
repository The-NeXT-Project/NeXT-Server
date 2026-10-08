// Package inbound holds the listener plumbing the node servers share.
package inbound

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const proxyProtocolHeaderTimeout = 5 * time.Second

type Options struct {
	Context context.Context
	Logger  logger.ContextLogger
	Listen  boxOption.ListenOptions
	// Network is the sing-box listener's own networks; set it to UDP for a
	// packet handler. TCP is always accepted through ServeTCP.
	Network       []string
	PacketHandler boxAdapter.PacketHandler

	ProxyProtocol        bool
	ProxyProtocolTrusted []string
}

// ConnectionHandler takes an accepted TCP connection in its own goroutine.
type ConnectionHandler func(ctx context.Context, conn net.Conn, metadata boxAdapter.InboundContext)

type Listener struct {
	ctx           context.Context
	logger        logger.ContextLogger
	listener      *listener.Listener
	proxyProtocol bool
	connPolicy    proxyproto.ConnPolicyFunc
	serving       sync.WaitGroup
}

func New(options Options) (*Listener, error) {
	l := &Listener{
		ctx:           options.Context,
		logger:        options.Logger,
		proxyProtocol: options.ProxyProtocol,
		listener: listener.New(listener.Options{
			Context:                  options.Context,
			Logger:                   options.Logger,
			Network:                  options.Network,
			Listen:                   options.Listen,
			PacketHandler:            options.PacketHandler,
			ThreadUnsafePacketWriter: true,
		}),
	}
	if len(options.ProxyProtocolTrusted) > 0 {
		policy, err := proxyproto.ConnLaxWhiteListPolicy(options.ProxyProtocolTrusted)
		if err != nil {
			return nil, E.Cause(err, "parse proxy_protocol_trusted")
		}
		l.connPolicy = policy
	}
	return l, nil
}

// Start starts the sing-box listener's own networks (the UDP packet loop).
func (l *Listener) Start() error {
	return l.listener.Start()
}

func (l *Listener) ListenUDP() (net.PacketConn, error) {
	return l.listener.ListenUDP()
}

func (l *Listener) PacketWriter() N.PacketWriter {
	return l.listener.PacketWriter()
}

func (l *Listener) UDPAddr() M.Socksaddr {
	return l.listener.UDPAddr()
}

// ListenTCP binds the TCP port. With PROXY protocol on, accepted connections
// read their header lazily in the connection's own goroutine, so a client
// that never sends one cannot stall the accept loop.
func (l *Listener) ListenTCP() (net.Listener, error) {
	tcpListener, err := l.listener.ListenTCP()
	if err != nil {
		return nil, err
	}
	if !l.proxyProtocol {
		return tcpListener, nil
	}
	return &proxyproto.Listener{
		Listener:          tcpListener,
		ConnPolicy:        l.connPolicy,
		ReadHeaderTimeout: proxyProtocolHeaderTimeout,
	}, nil
}

// ServeTCP accepts on tcpListener until it is closed.
func (l *Listener) ServeTCP(tcpListener net.Listener, handler ConnectionHandler) {
	go func() {
		var acceptDelay time.Duration
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				//nolint:staticcheck
				if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
					acceptDelay = min(max(2*acceptDelay, 5*time.Millisecond), time.Second)
					l.logger.Error(err, ", retrying in ", acceptDelay)
					time.Sleep(acceptDelay)
					continue
				}
				if !E.IsClosed(err) {
					l.logger.Error("tcp listener closed: ", err)
				}
				return
			}
			acceptDelay = 0
			go func() {
				var metadata boxAdapter.InboundContext
				// RemoteAddr reads the PROXY protocol header, if any.
				metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
				metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
				ctx := log.ContextWithNewID(l.ctx)
				l.logger.DebugContext(ctx, "inbound connection from ", metadata.Source)
				handler(ctx, conn, metadata)
			}()
		}
	}()
}

func (l *Listener) Close() error {
	return common.Close(l.listener)
}
