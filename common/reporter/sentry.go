//go:build with_sentry

package reporter

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/getsentry/sentry-go"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

const flushTimeout = 5 * time.Second

// New enables Sentry when options or SENTRY_DSN provide a DSN.
func New(options *option.SentryOptions) (Reporter, error) {
	sentryOptions := common.PtrValueOrDefault(options)
	if sentryOptions.DSN == "" && os.Getenv("SENTRY_DSN") == "" {
		if options != nil {
			return nil, E.New("sentry: missing dsn")
		}
		return nopReporter{}, nil
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              sentryOptions.DSN,
		Environment:      sentryOptions.Environment,
		Release:          "next-server@" + constant.Version,
		AttachStacktrace: true,
	})
	if err != nil {
		return nil, E.Cause(err, "initialize sentry")
	}
	reporter := &sentryReporter{limiter: newLimiter()}
	if sentryOptions.CrashFile != "" {
		err = reporter.watchCrashes(sentryOptions.CrashFile)
		if err != nil {
			sentry.Flush(flushTimeout)
			return nil, err
		}
	}
	return reporter, nil
}

type sentryReporter struct {
	limiter *limiter
}

func (r *sentryReporter) CaptureError(err error) {
	ok, suppressed := r.limiter.allow(err.Error())
	if !ok {
		return
	}
	sentry.WithScope(func(scope *sentry.Scope) {
		setSuppressed(scope, suppressed)
		sentry.CaptureException(err)
	})
}

func (r *sentryReporter) CaptureMessage(message string) {
	ok, suppressed := r.limiter.allow(message)
	if !ok {
		return
	}
	sentry.WithScope(func(scope *sentry.Scope) {
		setSuppressed(scope, suppressed)
		sentry.CaptureEvent(&sentry.Event{Level: sentry.LevelError, Message: message})
	})
}

// setSuppressed records how many similar reports the limiter held back.
func setSuppressed(scope *sentry.Scope, suppressed int) {
	if suppressed > 0 {
		scope.SetTag("suppressed", strconv.Itoa(suppressed))
	}
}

func (r *sentryReporter) Recover() {
	if recovered := recover(); recovered != nil {
		sentry.CurrentHub().Recover(recovered)
		sentry.Flush(flushTimeout)
		panic(recovered)
	}
}

func (r *sentryReporter) Close() error {
	sentry.Flush(flushTimeout)
	return nil
}

// watchCrashes reports the crash the previous run left in path, then has the
// runtime write the next fatal error there. Panics in goroutines started by
// sing-box cannot be recovered any other way.
func (r *sentryReporter) watchCrashes(path string) error {
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return E.Cause(err, "read crash file")
	}
	if len(content) > 0 {
		// The first line names the panic; the rest is the goroutine dump.
		message, _, _ := strings.Cut(string(content), "\n")
		sentry.CaptureEvent(&sentry.Event{
			Level:   sentry.LevelFatal,
			Message: "crashed: " + message,
			Attachments: []*sentry.Attachment{{
				Filename:    "crash.txt",
				ContentType: "text/plain",
				Payload:     content,
			}},
		})
		sentry.Flush(flushTimeout)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return E.Cause(err, "open crash file")
	}
	// The runtime keeps its own copy of the descriptor.
	defer file.Close()
	err = debug.SetCrashOutput(file, debug.CrashOptions{})
	if err != nil {
		return E.Cause(err, "set crash output")
	}
	return nil
}
