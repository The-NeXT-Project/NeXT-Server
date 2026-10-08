//go:build with_pprof

package profiler

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
)

func TestProfiler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	cpuProfile := filepath.Join(t.TempDir(), "cpu.pprof")
	profiler, err := Start(&option.PprofOptions{Listen: address, CPUProfile: cpuProfile}, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://" + address + "/debug/pprof/goroutine?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("pprof: ", response.Status)
	}
	if err = profiler.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(cpuProfile)
	if err != nil {
		t.Fatal(err)
	}
	// A profile is gzipped protobuf, which is what default.pgo must be.
	if !bytes.HasPrefix(content, []byte{0x1f, 0x8b}) {
		t.Fatal("cpu profile is not a pprof profile")
	}
}
