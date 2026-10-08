//go:build !with_sentry

package reporter

import (
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/option"
)

func TestSentryNeedsBuildTag(t *testing.T) {
	if _, err := New(&option.SentryOptions{DSN: "http://public@127.0.0.1/1"}); err == nil {
		t.Fatal("sentry configured in a build without it")
	}
	if _, err := New(nil); err != nil {
		t.Fatal(err)
	}
}
