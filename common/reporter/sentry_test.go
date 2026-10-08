//go:build with_sentry

package reporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
)

// fakeSentry collects the envelopes sentry-go posts.
func fakeSentry(t *testing.T) (dsn string, envelopes func() string) {
	var (
		access sync.Mutex
		bodies strings.Builder
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := io.ReadAll(r.Body)
		access.Lock()
		bodies.Write(content)
		access.Unlock()
	}))
	t.Cleanup(server.Close)
	return "http://public@" + strings.TrimPrefix(server.URL, "http://") + "/1", func() string {
		access.Lock()
		defer access.Unlock()
		return bodies.String()
	}
}

func TestSentryReportsErrorLogs(t *testing.T) {
	dsn, envelopes := fakeSentry(t)
	reporter, err := New(&option.SentryOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	logger := WrapLogger(log.NewNOPFactory().Logger(), reporter)
	logger.Info("routine message")
	logger.Error("report traffic: ", "panel unreachable")
	reporter.Close()
	if !strings.Contains(envelopes(), "report traffic: panel unreachable") {
		t.Fatal("error log not reported: ", envelopes())
	}
	if strings.Contains(envelopes(), "routine message") {
		t.Fatal("info log reported")
	}
}

func TestSentryReportsPreviousCrash(t *testing.T) {
	dsn, envelopes := fakeSentry(t)
	crashFile := filepath.Join(t.TempDir(), "crash")
	err := os.WriteFile(crashFile, []byte("panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := New(&option.SentryOptions{DSN: dsn, CrashFile: crashFile})
	if err != nil {
		t.Fatal(err)
	}
	// The runtime holds the file open, which Windows refuses to delete.
	t.Cleanup(func() { debug.SetCrashOutput(nil, debug.CrashOptions{}) })
	reporter.Close()
	if body := envelopes(); !strings.Contains(body, "crashed: panic: boom") || !strings.Contains(body, "goroutine 1 [running]") {
		t.Fatal("crash not reported with its dump: ", body)
	}
	if content, _ := os.ReadFile(crashFile); len(content) != 0 {
		t.Fatal("reported crash left in the file")
	}
}

func TestSentryNeedsDSN(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	if _, err := New(&option.SentryOptions{}); err == nil {
		t.Fatal("configured without a dsn")
	}
	reporter, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, isNop := reporter.(nopReporter); !isNop {
		t.Fatal("enabled without configuration or SENTRY_DSN")
	}
}

func TestCrashFileCapturesGoroutinePanic(t *testing.T) {
	if crashFile := os.Getenv("NEXT_SERVER_CRASH_FILE"); crashFile != "" {
		// The child: crash the way a panic in a connection would.
		if _, err := New(&option.SentryOptions{DSN: os.Getenv("NEXT_SERVER_CRASH_DSN"), CrashFile: crashFile}); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			panic("connection goroutine panic")
		}()
		<-done
		return
	}
	dsn, _ := fakeSentry(t)
	crashFile := filepath.Join(t.TempDir(), "crash")
	command := exec.Command(os.Args[0], "-test.run=^TestCrashFileCapturesGoroutinePanic$")
	command.Env = append(os.Environ(), "NEXT_SERVER_CRASH_FILE="+crashFile, "NEXT_SERVER_CRASH_DSN="+dsn)
	if err := command.Run(); err == nil {
		t.Fatal("the child did not crash")
	}
	content, err := os.ReadFile(crashFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), "panic: connection goroutine panic") {
		t.Fatal("crash file: ", string(content))
	}
}

func TestSentryLimitsRepeatedErrors(t *testing.T) {
	dsn, envelopes := fakeSentry(t)
	reporter, err := New(&option.SentryOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	logger := WrapLogger(log.NewNOPFactory().Logger(), reporter)
	for i := range 500 {
		logger.Error("report traffic: dial tcp 10.0.0.1:", 40000+i, ": connection refused")
	}
	reporter.Close()
	if count := strings.Count(envelopes(), "connection refused"); count != 1 {
		t.Fatal("sent ", count, " events for one repeated error")
	}
}
