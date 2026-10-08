package nextserver

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/common/profiler"
	"github.com/The-NeXT-Project/NeXT-Server/common/reporter"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type Instance struct {
	options    option.Options
	logFactory log.Factory
	logger     log.ContextLogger
	reporter   reporter.Reporter
	profiler   io.Closer
	servers    []*Server
}

func New(ctx context.Context, options option.Options) (*Instance, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("no servers configured")
	}
	// First, so that every later failure is reported.
	errorReporter, err := reporter.New(options.Sentry)
	if err != nil {
		return nil, err
	}
	instance, err := newInstance(ctx, options, errorReporter)
	if err != nil {
		errorReporter.CaptureError(err)
		errorReporter.Close()
		return nil, err
	}
	return instance, nil
}

func newInstance(ctx context.Context, options option.Options, errorReporter reporter.Reporter) (*Instance, error) {
	logFactory, err := log.New(log.Options{
		Context:       ctx,
		Options:       common.PtrValueOrDefault(options.Log),
		DefaultWriter: os.Stderr,
		BaseTime:      time.Now(),
	})
	if err != nil {
		return nil, E.Cause(err, "create logger")
	}
	instance := &Instance{
		options:    options,
		logFactory: logFactory,
		logger:     reporter.WrapLogger(logFactory.Logger(), errorReporter),
		reporter:   errorReporter,
	}
	for index, serverOptions := range options.Servers {
		logger := instance.logger
		if len(options.Servers) > 1 {
			logger = reporter.WrapLogger(logFactory.NewLogger(F.ToString("server[", index, "]")), errorReporter)
		}
		server, err := NewServer(ctx, logger, errorReporter, serverOptions)
		if err != nil {
			return nil, E.Cause(err, "server[", index, "]")
		}
		instance.servers = append(instance.servers, server)
	}
	return instance, nil
}

func (i *Instance) Start() error {
	err := i.start()
	if err != nil {
		i.reporter.CaptureError(err)
	}
	return err
}

func (i *Instance) start() error {
	err := i.logFactory.Start()
	if err != nil {
		return E.Cause(err, "start logger")
	}
	if missing := constant.MissingDefaultBuildTags(); len(missing) > 0 {
		i.logger.Warn("built without -tags ", strings.Join(missing, ","), ", the features they enable are unavailable")
	}
	i.profiler, err = profiler.Start(i.options.Pprof, i.logger)
	if err != nil {
		return err
	}
	for index, server := range i.servers {
		err = server.Start()
		if err != nil {
			return E.Cause(err, "server[", index, "]")
		}
	}
	i.logger.Info("next-server ", constant.Version, " started")
	return nil
}

// Close stops every server, then the profiler, so that its CPU profile
// covers the shutdown, and sends pending error reports last.
func (i *Instance) Close() error {
	var errs []error
	for index, server := range i.servers {
		err := server.Close()
		if err != nil {
			errs = append(errs, E.Cause(err, "server[", index, "]"))
		}
	}
	if i.profiler != nil {
		errs = append(errs, i.profiler.Close())
	}
	errs = append(errs, i.logFactory.Close(), i.reporter.Close())
	return E.Errors(errs...)
}
