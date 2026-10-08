//go:build with_pprof

// Package profiler exposes Go's profiler in builds with -tags with_pprof.
package profiler

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	runtimePprof "runtime/pprof"

	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// Start serves pprof and records a CPU profile as configured. Closing it
// stops both and finishes the profile file.
func Start(options *option.PprofOptions, logger log.ContextLogger) (io.Closer, error) {
	if options == nil {
		return nopCloser{}, nil
	}
	profiler := &profiler{}
	if options.CPUProfile != "" {
		file, err := os.Create(options.CPUProfile)
		if err != nil {
			return nil, E.Cause(err, "create cpu profile")
		}
		err = runtimePprof.StartCPUProfile(file)
		if err != nil {
			file.Close()
			return nil, E.Cause(err, "start cpu profile")
		}
		profiler.cpuProfile = file
		logger.Info("recording cpu profile to ", options.CPUProfile)
	}
	if options.Listen != "" {
		listener, err := net.Listen("tcp", options.Listen)
		if err != nil {
			profiler.Close()
			return nil, E.Cause(err, "listen pprof")
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		profiler.server = &http.Server{Handler: mux}
		go func() {
			err := profiler.server.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("pprof server: ", err)
			}
		}()
		logger.Info("pprof listening on http://", listener.Addr(), "/debug/pprof/")
	}
	return profiler, nil
}

type profiler struct {
	cpuProfile *os.File
	server     *http.Server
}

func (p *profiler) Close() error {
	var err error
	if p.server != nil {
		err = p.server.Close()
	}
	if p.cpuProfile != nil {
		runtimePprof.StopCPUProfile()
		err = E.Errors(err, p.cpuProfile.Close())
	}
	return err
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
