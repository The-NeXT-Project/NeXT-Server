package reporter

import (
	"regexp"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// repeatWindow is how long a message is not sent again.
	repeatWindow = 10 * time.Minute
	// eventBurst and eventInterval cap what one process sends in total.
	eventBurst    = 10
	eventInterval = 10 * time.Second
	maxTracked    = 1000
)

// variablePart matches what differs between reports of one problem: IDs,
// ports, counts and addresses.
var variablePart = regexp.MustCompile(`[0-9a-fA-F]*[0-9][0-9a-fA-F]*`)

// limiter keeps an error storm from turning into an event storm: a message
// differing only in numbers is one problem, sent once per window, and all
// messages together stay within a rate.
type limiter struct {
	access sync.Mutex
	rate   *rate.Limiter
	now    func() time.Time
	seen   map[string]*seenMessage
}

type seenMessage struct {
	sent       time.Time
	suppressed int
}

func newLimiter() *limiter {
	return &limiter{
		rate: rate.NewLimiter(rate.Every(eventInterval), eventBurst),
		now:  time.Now,
		seen: make(map[string]*seenMessage),
	}
}

// allow reports whether message may be sent now, and how many like it were
// held back since the last one that was.
func (l *limiter) allow(message string) (bool, int) {
	key := variablePart.ReplaceAllString(message, "#")
	now := l.now()
	l.access.Lock()
	defer l.access.Unlock()
	seen := l.seen[key]
	if seen != nil && now.Sub(seen.sent) < repeatWindow {
		seen.suppressed++
		return false, 0
	}
	if !l.rate.AllowN(now, 1) {
		if seen != nil {
			seen.suppressed++
		}
		return false, 0
	}
	suppressed := 0
	if seen != nil {
		suppressed = seen.suppressed
	}
	if len(l.seen) >= maxTracked {
		for key, it := range l.seen {
			if now.Sub(it.sent) >= repeatWindow {
				delete(l.seen, key)
			}
		}
	}
	l.seen[key] = &seenMessage{sent: now}
	return true, suppressed
}
