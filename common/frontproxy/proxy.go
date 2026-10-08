package frontproxy

import (
	"github.com/The-NeXT-Project/NeXT-Server/option"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
)

// New returns a dialer that connects through the front proxy. Domains are
// sent to the proxy unresolved; ResolveDomain is applied by the router.
func New(dialer N.Dialer, options option.FrontProxyOptions) (N.Dialer, error) {
	dialer = serverDialer{dialer}
	var proxyDialer N.Dialer
	if options.Type == option.FrontProxyTypeHTTP {
		proxyDialer = http.NewClient(http.Options{
			Dialer:   dialer,
			Server:   M.ParseSocksaddr(options.Server),
			Username: options.Username,
			Password: options.Password,
		})
	} else {
		var socksVersion socks.Version
		switch options.Type {
		case "", option.FrontProxyTypeSOCKS5:
			socksVersion = socks.Version5
		case option.FrontProxyTypeSOCKS4:
			socksVersion = socks.Version4
		case option.FrontProxyTypeSOCKS4A:
			socksVersion = socks.Version4A
		default:
			return nil, E.New("unknown front proxy type: ", options.Type)
		}
		proxyDialer = socks.NewClient(dialer, M.ParseSocksaddr(options.Server), socksVersion, options.Username, options.Password)
	}
	return proxyDialer, nil
}
