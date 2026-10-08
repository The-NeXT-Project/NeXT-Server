// Package reporter sends errors to Sentry in builds with -tags with_sentry.
package reporter

import (
	"context"

	"github.com/sagernet/sing-box/log"
	F "github.com/sagernet/sing/common/format"
)

type Reporter interface {
	CaptureError(err error)
	CaptureMessage(message string)
	// Recover reports a panic in progress and panics again, for use with defer.
	Recover()
	// Close sends pending events.
	Close() error
}

type nopReporter struct{}

func (nopReporter) CaptureError(error)    {}
func (nopReporter) CaptureMessage(string) {}
func (nopReporter) Recover()              {}
func (nopReporter) Close() error          { return nil }

// WrapLogger reports what logger logs at error level and above. Lower levels
// cost nothing extra.
func WrapLogger(logger log.ContextLogger, reporter Reporter) log.ContextLogger {
	if _, isNop := reporter.(nopReporter); isNop {
		return logger
	}
	return &reportingLogger{logger, reporter}
}

type reportingLogger struct {
	log.ContextLogger
	reporter Reporter
}

func (l *reportingLogger) Error(args ...any) {
	l.ContextLogger.Error(args...)
	l.reporter.CaptureMessage(F.ToString(args...))
}

func (l *reportingLogger) ErrorContext(ctx context.Context, args ...any) {
	l.ContextLogger.ErrorContext(ctx, args...)
	l.reporter.CaptureMessage(F.ToString(args...))
}

func (l *reportingLogger) Fatal(args ...any) {
	l.reporter.CaptureMessage(F.ToString(args...))
	l.reporter.Close()
	l.ContextLogger.Fatal(args...)
}

func (l *reportingLogger) FatalContext(ctx context.Context, args ...any) {
	l.reporter.CaptureMessage(F.ToString(args...))
	l.reporter.Close()
	l.ContextLogger.FatalContext(ctx, args...)
}

func (l *reportingLogger) Panic(args ...any) {
	l.reporter.CaptureMessage(F.ToString(args...))
	l.reporter.Close()
	l.ContextLogger.Panic(args...)
}

func (l *reportingLogger) PanicContext(ctx context.Context, args ...any) {
	l.reporter.CaptureMessage(F.ToString(args...))
	l.reporter.Close()
	l.ContextLogger.PanicContext(ctx, args...)
}
