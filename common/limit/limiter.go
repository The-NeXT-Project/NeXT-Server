// Package limit throttles connections with a token bucket per direction.
package limit

import (
	"context"
	"math"
	"net"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/time/rate"
)

// minBurst keeps a single UDP datagram or read buffer within one bucket.
const minBurst = 64 * 1024

// Limiter is shared by every connection of one user. Upload is what the client
// sends, download what it receives; each direction gets the full rate.
type Limiter struct {
	upload   *rate.Limiter
	download *rate.Limiter
}

// New returns a limiter for bytesPerSecond in each direction, which must be positive.
func New(bytesPerSecond uint64) *Limiter {
	limit, burst := bucket(bytesPerSecond)
	return &Limiter{
		upload:   rate.NewLimiter(limit, burst),
		download: rate.NewLimiter(limit, burst),
	}
}

// SetLimit changes the rate for existing connections too.
func (l *Limiter) SetLimit(bytesPerSecond uint64) {
	limit, burst := bucket(bytesPerSecond)
	for _, limiter := range []*rate.Limiter{l.upload, l.download} {
		limiter.SetLimit(limit)
		limiter.SetBurst(burst)
	}
}

func bucket(bytesPerSecond uint64) (rate.Limit, int) {
	return rate.Limit(bytesPerSecond), int(min(max(bytesPerSecond, minBurst), math.MaxInt32))
}

// wait blocks until n bytes may pass, taking at most one burst at a time
// because WaitN refuses requests larger than the burst.
func wait(ctx context.Context, limiter *rate.Limiter, n int) error {
	for n > 0 {
		chunk := min(n, limiter.Burst())
		err := limiter.WaitN(ctx, chunk)
		if err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// Conn throttles conn, the client side of a proxied connection.
func (l *Limiter) Conn(ctx context.Context, conn net.Conn) net.Conn {
	return &limitedConn{Conn: conn, ctx: ctx, limiter: l}
}

// PacketConn throttles conn, the client side of a proxied packet connection.
func (l *Limiter) PacketConn(ctx context.Context, conn N.PacketConn) N.PacketConn {
	return &limitedPacketConn{PacketConn: conn, ctx: ctx, limiter: l}
}

// limitedConn exposes its upstream for type casts such as handshake reporting,
// but is not replaceable, so copy loops cannot splice around it.
type limitedConn struct {
	net.Conn
	ctx     context.Context
	limiter *Limiter
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if burst := c.limiter.upload.Burst(); len(p) > burst {
		p = p[:burst]
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		if waitErr := wait(c.ctx, c.limiter.upload, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	err := wait(c.ctx, c.limiter.download, len(p))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *limitedConn) Upstream() any {
	return c.Conn
}

type limitedPacketConn struct {
	N.PacketConn
	ctx     context.Context
	limiter *Limiter
}

func (c *limitedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	return destination, wait(c.ctx, c.limiter.upload, buffer.Len())
}

func (c *limitedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := wait(c.ctx, c.limiter.download, buffer.Len())
	if err != nil {
		buffer.Release()
		return err
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *limitedPacketConn) Upstream() any {
	return c.PacketConn
}
