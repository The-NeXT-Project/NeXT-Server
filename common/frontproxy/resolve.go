package frontproxy

import (
	"context"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// serverDialer resolves the proxy server's own address, which sing-box's
// default dialer refuses to do.
type serverDialer struct {
	N.Dialer
}

func (d serverDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsFqdn() {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn)
	if err != nil {
		return nil, E.Cause(err, "resolve front proxy server")
	}
	return N.DialSerial(ctx, d.Dialer, network, destination, addresses)
}
