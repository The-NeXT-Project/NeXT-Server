package nextserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/common/abuse"
	"github.com/The-NeXT-Project/NeXT-Server/option"
)

func signatureNames(set *signatureSet) []string {
	var names []string
	for _, signature := range set.current() {
		names = append(names, signature.Name)
	}
	return names
}

func TestSignatureFileUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signatures.json")
	set, err := newSignatureSet(option.AbuseSignaturesOptions{Path: path}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	builtin := len(set.current())

	// A missing file is reported once and adds nothing.
	if _, err = set.refresh(ctx); err == nil {
		t.Error("missing file not reported")
	}
	if _, err = set.refresh(ctx); err != nil {
		t.Error("missing file reported again: ", err)
	}
	write := func(content string, age time.Duration) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		// Each write gets its own modification time, however fast the test.
		stamp := time.Now().Add(-age)
		os.Chtimes(path, stamp, stamp)
	}

	write(`{"signatures": [{"name": "custom", "regex": "evil-path"}, {"name": "stratum", "disabled": true}]}`, 3*time.Hour)
	summary, err := set.refresh(ctx)
	if err != nil || !strings.Contains(summary, "2 from the file") {
		t.Fatal(summary, err)
	}
	names := signatureNames(set)
	if !slices.Contains(names, "custom") || slices.Contains(names, "stratum") || len(names) != builtin {
		t.Fatal("after the update: ", names)
	}
	if hit, found := abuse.MatchSignatures(set.current(), []byte("GET /evil-path HTTP/1.1")); !found || hit.Name != "custom" {
		t.Fatal("the new signature does not match")
	}
	// Unchanged, nothing happens.
	if summary, err = set.refresh(ctx); summary != "" || err != nil {
		t.Error("unchanged file: ", summary, err)
	}

	// A broken update keeps the last good signatures and is reported once.
	write(`{"signatures": [{"name": "custom", "regx": "typo"}]}`, 2*time.Hour)
	if _, err = set.refresh(ctx); err == nil {
		t.Error("broken file not reported")
	}
	if !slices.Contains(signatureNames(set), "custom") {
		t.Error("lost the last good signatures")
	}
	if _, err = set.refresh(ctx); err != nil {
		t.Error("broken file reported again: ", err)
	}

	// Removing the file removes its signatures.
	os.Remove(path)
	set.refresh(ctx)
	if names = signatureNames(set); slices.Contains(names, "custom") || !slices.Contains(names, "stratum") {
		t.Error("after removing the file: ", names)
	}
}

func TestSignatureURLUpdates(t *testing.T) {
	var requests atomic.Int32
	content := `{"signatures": [{"name": "remote", "kind": "mining", "regex": "pool-login"}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(content))
	}))
	defer server.Close()

	if _, err := newSignatureSet(option.AbuseSignaturesOptions{URL: "http://example.com/s.json"}, true, true); err == nil {
		t.Error("accepted a plain HTTP URL")
	}
	// Only mining is on: exploit signatures are left out.
	set, err := newSignatureSet(option.AbuseSignaturesOptions{URL: server.URL}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	set.client = server.Client()
	ctx := context.Background()
	if _, err = set.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if hit, found := abuse.MatchSignatures(set.current(), []byte(`{"pool-login": 1}`)); !found || hit.Kind != abuse.Mining {
		t.Fatal("remote signature missing: ", signatureNames(set))
	}
	if _, found := abuse.MatchSignatures(set.current(), []byte("GET /../../../../etc/passwd HTTP/1.1")); found {
		t.Error("exploit signatures applied with exploits off")
	}
	if summary, err := set.refresh(ctx); summary != "" || err != nil || requests.Load() != 2 {
		t.Error("second fetch: ", summary, err, requests.Load())
	}

	// The server going away keeps what it gave, and is reported once.
	server.Close()
	if _, err = set.refresh(ctx); err == nil {
		t.Error("unreachable URL not reported")
	}
	if _, err = set.refresh(ctx); err != nil {
		t.Error("unreachable URL reported again: ", err)
	}
	if !slices.Contains(signatureNames(set), "remote") {
		t.Error("lost the remote signatures")
	}
}
