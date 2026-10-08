package nextserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/common/reporter"

	"github.com/sagernet/sing-box/log"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/http2"
)

func trafficOf(items []adapter.UserTraffic) map[int][2]int64 {
	result := make(map[int][2]int64)
	for _, item := range items {
		result[item.UserID] = [2]int64{item.Upload, item.Download}
	}
	return result
}

func TestUserTableKeepsTrafficAcrossUpdates(t *testing.T) {
	table := newUserTable(context.Background())
	table.update([]adapter.User{{ID: 1}, {ID: 2}}, 0)
	kept, removed := table.get(1), table.get(2)
	kept.upload.Add(10)
	removed.download.Add(20)

	table.update([]adapter.User{{ID: 1}, {ID: 3}}, 0)
	if table.get(1) != kept {
		t.Fatal("a kept user got new state")
	}
	if removed.ctx.Err() == nil {
		t.Fatal("removing a user did not cancel their connections")
	}
	if table.get(2) != nil {
		t.Fatal("removed user is still served")
	}
	traffic := trafficOf(table.collectTraffic())
	if traffic[1] != [2]int64{10, 0} || traffic[2] != [2]int64{0, 20} {
		t.Fatal("traffic lost across an update: ", traffic)
	}
	// Reported and idle, the retired user is dropped.
	table.collectTraffic()
	if len(table.retired) != 0 {
		t.Fatal("retired user kept after its traffic was reported")
	}
}

func TestUserTableRestoresFailedReports(t *testing.T) {
	table := newUserTable(context.Background())
	table.update([]adapter.User{{ID: 1}}, 0)
	table.get(1).upload.Add(5)
	items := table.collectTraffic()
	table.restoreTraffic(items)
	// A report for a user dropped in between must not vanish either.
	table.restoreTraffic([]adapter.UserTraffic{{UserID: 9, Download: 7}})
	traffic := trafficOf(table.collectTraffic())
	if traffic[1] != [2]int64{5, 0} || traffic[9] != [2]int64{0, 7} {
		t.Fatal("restored traffic: ", traffic)
	}
}

func TestUserSpeedLimit(t *testing.T) {
	table := newUserTable(context.Background())
	table.update([]adapter.User{{ID: 1, SpeedLimit: 100}, {ID: 2}}, 0)
	if table.get(1).limiter.Load() == nil || table.get(2).limiter.Load() != nil {
		t.Fatal("limits not applied")
	}
	// The node limit applies to users without their own.
	table.update([]adapter.User{{ID: 1, SpeedLimit: 100}, {ID: 2}}, 50)
	if table.get(2).limiter.Load() == nil {
		t.Fatal("node limit not applied")
	}
	for _, testCase := range [][3]uint64{{0, 0, 0}, {0, 5, 5}, {5, 0, 5}, {3, 5, 3}, {5, 3, 3}} {
		if got := effectiveLimit(testCase[0], testCase[1]); got != testCase[2] {
			t.Errorf("effectiveLimit(%d, %d) = %d", testCase[0], testCase[1], got)
		}
	}
}

func TestOnlineIPs(t *testing.T) {
	state := newUserState(context.Background(), 1)
	start := time.Now()
	address := netip.MustParseAddr("::ffff:1.2.3.4")
	done := state.open(address)
	if ips := state.onlineIPs(start); len(ips) != 1 || ips[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatal("active address: ", ips)
	}
	done()
	done()
	if state.activeConnections() != 0 {
		t.Fatal("closing twice was counted twice")
	}
	// Seen since the last report, so reported once more, then forgotten.
	if len(state.onlineIPs(start)) != 1 {
		t.Fatal("recently closed address not reported")
	}
	if ips := state.onlineIPs(time.Now().Add(time.Second)); len(ips) != 0 {
		t.Fatal("idle address still reported: ", ips)
	}
}

func TestAuditor(t *testing.T) {
	auditor := newAuditor()
	if auditor.enabled() {
		t.Fatal("enabled without rules")
	}
	auditor.setRules([]adapter.DetectRule{
		{ID: 1, Type: adapter.DetectRuleTypePlain, Regexp: mustCompile(t, `torrent`)},
		{ID: 2, Type: adapter.DetectRuleTypeHex, Regexp: mustCompile(t, `^1603`)},
	})
	cases := []struct {
		host, domain string
		payload      []byte
		rule         int
	}{
		{"tracker.torrent.example", "", nil, 1},
		{"1.2.3.4", "x.torrent.example", nil, 1},
		{"1.2.3.4", "", []byte("GET /announce?torrent"), 1},
		{"1.2.3.4", "", []byte{0x16, 0x03, 0x01}, 2},
		{"example.com", "", []byte("hello"), 0},
	}
	for _, testCase := range cases {
		rule, hit := auditor.match(testCase.host, testCase.domain, testCase.payload)
		if (testCase.rule == 0 && hit) || (testCase.rule != 0 && rule.ID != testCase.rule) {
			t.Errorf("%+v: got rule %d, hit %v", testCase, rule.ID, hit)
		}
	}
	auditor.record(1, 1)
	auditor.record(1, 1)
	logs := auditor.collect()
	if len(logs) != 1 {
		t.Fatal("hits not deduplicated: ", logs)
	}
	auditor.restore(logs)
	if len(auditor.collect()) != 1 {
		t.Fatal("restored hits lost")
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestConnectionClosedClassification(t *testing.T) {
	for _, testCase := range []struct {
		err    error
		closed bool
	}{
		{http2.StreamError{StreamID: 1, Code: http2.ErrCodeNo}, true},
		{E.Cause(http2.StreamError{StreamID: 3, Code: http2.ErrCodeCancel}, "read"), true},
		{http2.StreamError{StreamID: 5, Code: http2.ErrCodeInternal}, false},
		{E.New("connection reset"), false},
		// A dial over several addresses the client stopped waiting for.
		{E.Errors(
			&net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled},
			&net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled},
		), true},
		{E.Cause(errors.New("http2: stream closed"), "download"), true},
		// The destination failing is worth a warning.
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
	} {
		if got := isConnectionClosed([]any{"connection upload closed: ", testCase.err}); got != testCase.closed {
			t.Errorf("%v: closed = %v", testCase.err, got)
		}
	}
}

// On Go 1.27 the HTTP/2 server behind x/net/http2 is net/http's internal
// copy, so a real reset must be recognized through its conversion, not just
// an x/net value built by hand.
func TestConnectionClosedFromNetHTTP(t *testing.T) {
	readErr := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, err := io.Copy(io.Discard, r.Body)
		readErr <- err
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	body, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, body)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatal("not HTTP/2: ", response.Proto)
	}
	// The client resets the stream with CANCEL.
	writer.Write([]byte("partial"))
	writer.CloseWithError(errors.New("abort"))
	response.Body.Close()
	cancel()
	select {
	case err = <-readErr:
	case <-time.After(5 * time.Second):
		t.Fatal("server read did not end")
	}
	t.Logf("server saw %T: %v", err, err)
	if !isConnectionClosed([]any{"connection upload closed: ", err}) {
		t.Fatalf("not recognized: %T %v", err, err)
	}
}

type capturingReporter struct {
	access   sync.Mutex
	messages []string
}

func (r *capturingReporter) CaptureError(err error) { r.CaptureMessage(err.Error()) }
func (r *capturingReporter) CaptureMessage(message string) {
	r.access.Lock()
	r.messages = append(r.messages, message)
	r.access.Unlock()
}
func (r *capturingReporter) Recover()     {}
func (r *capturingReporter) Close() error { return nil }

// Connection failures stay out of error reports; server failures do not.
func TestConnectionErrorsAreNotReported(t *testing.T) {
	captured := &capturingReporter{}
	logger := connectionLogger{reporter.WrapLogger(log.NewNOPFactory().Logger(), captured)}
	ctx := context.Background()
	logger.ErrorContext(ctx, E.Cause(errors.New("bad path: /robots.txt"), "process connection from 1.2.3.4:5"))
	logger.ErrorContext(ctx, "open connection to 1.2.3.4:443: ", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
	logger.ErrorContext(ctx, "connection upload closed: ", http2.StreamError{StreamID: 1, Code: http2.ErrCodeNo})
	logger.Error("tcp listener closed: ", errors.New("accept: too many open files"))
	if len(captured.messages) != 1 || captured.messages[0] != "tcp listener closed: accept: too many open files" {
		t.Fatal("reported: ", captured.messages)
	}
}
