//go:build !with_pprof

package profiler

import (
	"io"

	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

func Start(options *option.PprofOptions, logger log.ContextLogger) (io.Closer, error) {
	if options != nil {
		return nil, E.New("pprof is not included in this build, rebuild with -tags with_pprof")
	}
	return nopCloser{}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
