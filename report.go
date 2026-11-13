package nextserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// reportOutbox delivers one kind of report (traffic, detect logs) to the
// panel, one batch at a time, so that a batch is never counted twice.
//
// Every batch gets a random report ID. When sending fails without an answer
// from the panel (a timeout, a reset connection, a 5xx from a proxy in front
// of it), the panel may well have recorded the batch already, so it stays
// pending and is sent again unchanged, with the same ID, on the next flush;
// the panel recognizes an ID it has recorded and answers that it is a
// duplicate. Nothing new is collected while a batch is pending: new counts
// keep accumulating at their source and are collected once it has gone
// through. Merging the failed batch back into the counters instead, as
// before, made the retry a different batch and billed the same bytes twice
// whenever the panel had committed the first.
//
// A refusal (a 4xx answer) is different: the panel validates and
// authenticates a report before recording any of it, so a refused batch was
// not recorded. It goes back to its source and travels in a later batch with
// a new ID. Sending it again unchanged could not succeed if the panel refuses
// it for its content, and would block the reports behind it for good.
//
// An outbox belongs to the push loop and, after the loop has stopped, to
// Close; it is not safe for concurrent use.
type reportOutbox[T any] struct {
	name   string
	logger log.ContextLogger
	// collect takes the counts gathered since the last batch.
	collect func() []T
	// restore puts back the counts of a refused batch.
	restore func([]T)
	send    func(ctx context.Context, reportID string, items []T) error

	id    string
	items []T
	// failures counts the attempts that failed for the pending batch.
	failures int
}

// flush sends the pending batch, if any, and then a new one if the pending
// batch went through and there is something new.
func (o *reportOutbox[T]) flush(ctx context.Context) error {
	if o.items != nil {
		err := o.deliver(ctx)
		if err != nil {
			return err
		}
	}
	items := o.collect()
	if len(items) == 0 {
		return nil
	}
	o.id, o.items, o.failures = newReportID(), items, 0
	return o.deliver(ctx)
}

func (o *reportOutbox[T]) deliver(ctx context.Context) error {
	err := o.send(ctx, o.id, o.items)
	switch {
	case err == nil:
		if o.failures > 0 {
			o.logger.Info(o.name, " batch ", o.id, " delivered after ", o.failures, " failed attempts")
		}
	case adapter.IsRefused(err):
		o.restore(o.items)
		err = E.Cause(err, "refused; its counts go into the next batch")
	default:
		o.failures++
		return E.Cause(err, "batch ", o.id, " kept for the next attempt (", o.failures, " failed)")
	}
	o.id, o.items, o.failures = "", nil, 0
	return err
}

// pending reports whether a batch is waiting to be sent again.
func (o *reportOutbox[T]) pending() bool {
	return o.items != nil
}

// newReportID returns 32 random hex digits, unique enough that the panel
// never mistakes one batch for another.
func newReportID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}
