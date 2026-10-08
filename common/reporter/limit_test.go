package reporter

import (
	"strconv"
	"testing"
	"time"
)

func TestLimiterSendsAProblemOnce(t *testing.T) {
	limiter := newLimiter()
	now := time.Unix(0, 0)
	limiter.now = func() time.Time { return now }
	sent := 0
	for i := range 1000 {
		// The same problem with a different connection each time.
		if ok, _ := limiter.allow("process connection from 10.0.0." + strconv.Itoa(i%250) + ":" + strconv.Itoa(40000+i) + ": eof"); ok {
			sent++
		}
	}
	if sent != 1 {
		t.Fatal("sent ", sent, " reports of one problem")
	}
	now = now.Add(repeatWindow)
	ok, suppressed := limiter.allow("process connection from 10.0.0.1:1: eof")
	if !ok || suppressed != 999 {
		t.Fatal("after the window: sent ", ok, ", suppressed ", suppressed)
	}
}

func TestLimiterCapsDistinctProblems(t *testing.T) {
	limiter := newLimiter()
	now := time.Unix(0, 0)
	limiter.now = func() time.Time { return now }
	sent := 0
	for i := range 100 {
		if ok, _ := limiter.allow("problem " + string(rune('a'+i%26)) + string(rune('a'+i/26))); ok {
			sent++
		}
	}
	if sent != eventBurst {
		t.Fatal("sent ", sent, " at once, want the burst of ", eventBurst)
	}
	now = now.Add(eventInterval)
	if ok, _ := limiter.allow("a new problem"); !ok {
		t.Fatal("the rate did not refill")
	}
}
