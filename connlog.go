package nextserver

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

// connectionLogger is the logger of everything that handles connections:
// node servers, their transports and the connection manager. sing-box and
// sing-mux log what goes wrong with one connection through ErrorContext, and
// what goes wrong with the server through Error. A connection failing is not
// a server error, and on a public node it happens constantly (clients going
// away, unreachable destinations, scanners), so ErrorContext is logged at
// debug when the client or peer ended the connection and at warn otherwise.
// Neither reaches the error reporter.
type connectionLogger struct {
	log.ContextLogger
}

func (l connectionLogger) ErrorContext(ctx context.Context, args ...any) {
	if isConnectionClosed(args) {
		l.ContextLogger.DebugContext(ctx, args...)
	} else {
		l.ContextLogger.WarnContext(ctx, args...)
	}
}

// isConnectionClosed reports whether the logged error only says that the
// other side went away.
func isConnectionClosed(args []any) bool {
	for _, arg := range args {
		err, isError := arg.(error)
		if !isError {
			continue
		}
		if E.IsClosedOrCanceled(err) || errors.Is(err, context.Canceled) {
			return true
		}
		// On Go 1.27 these come from net/http's internal HTTP/2, which
		// converts to the x/net types through As.
		var streamErr http2.StreamError
		if errors.As(err, &streamErr) && (streamErr.Code == http2.ErrCodeNo || streamErr.Code == http2.ErrCodeCancel) {
			return true
		}
		if isMessage(err, "http2: stream closed") {
			return true
		}
	}
	return false
}

// isMessage matches sentinel errors that are not exported, along the wrap chain.
func isMessage(err error, message string) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if err.Error() == message {
			return true
		}
	}
	return false
}
