package abuse

import (
	"bytes"
	"encoding/json"
	"regexp"

	E "github.com/sagernet/sing/common/exceptions"
)

// Signature kinds, as written in a signature file.
const (
	SignatureExploit = "exploit"
	SignatureMining  = "mining"
)

// Signature is a compiled signature, matched against the first payload of a
// TCP connection.
type Signature struct {
	Name   string
	Kind   Kind
	Regexp *regexp.Regexp
}

// SignatureSpec is a signature as written in a signature file. A spec whose
// name is already taken replaces that signature; one with Disabled set
// removes it, so an update can fix or retire a built-in one.
type SignatureSpec struct {
	Name string `json:"name"`
	// Kind is "exploit" (the default) or "mining".
	Kind     string `json:"kind,omitempty"`
	Regex    string `json:"regex,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

// SignatureFile is the format of a signature update, from a file or a URL.
type SignatureFile struct {
	Signatures []SignatureSpec `json:"signatures"`
}

// BuiltinSignatures see only the first payload of a connection, so HTTPS,
// TLS mining and later requests on a kept-alive connection pass.
//
// The exploit signatures catch what scanners and botnets send to find and
// take over servers over plain HTTP. The mining ones catch miners logging in
// to a pool over plain Stratum. Each was checked against samples and
// look-alikes in Go's RE2, and the exploit ones also in PHP's PCRE, which the
// panel validates its detect rules with.
var BuiltinSignatures = []SignatureSpec{
	{Name: "log4shell", Regex: `(?i)\$\{[^}]{0,30}?(jndi\s*:|\$\{\s*(lower|upper|env|sys|date|::-))`},
	{Name: "sql-injection", Regex: `(?i)(union(\s|\+|%20|/\*.{0,20}?\*/)+(all(\s|\+|%20)+)?select(\s|\+|%20|\(|/\*)|information_schema\.|(and|or)(\s|\+|%20)+(sleep|pg_sleep|benchmark)\(\s*\d)`},
	{Name: "path-traversal", Regex: `(?i)((\.|%2e){2}(/|%2f|\\|%5c)){2,}[^ ]{0,60}?(etc(/|%2f)(passwd|shadow)|win\.ini|boot\.ini|proc(/|%2f)self(/|%2f)environ)`},
	{Name: "malware-dropper", Regex: "(?i)((;|%3b|\\||%7c|&&|%26%26|\\$\\(|%24%28|`)(\\s|\\+|%20)*(wget|curl|tftp|busybox)(\\s|\\+|%20|\\$\\{IFS\\})|/bin/busybox|chmod(\\s|\\+|%20)+(777|\\+x)(\\s|\\+|%20)+/tmp)"},
	{Name: "known-exploit", Regex: `(?i)((allow_url_include|auto_prepend_file)(=|%3d)|class\.module\.classloader|/cgi-bin/(\.%2e|%%32%65)/)`},
	{Name: "stratum", Kind: SignatureMining, Regex: `"method"\s*:\s*"mining\.(subscribe|authorize|submit|extranonce\.subscribe)"`},
	{Name: "miner-login", Kind: SignatureMining, Regex: `(?i)"agent"\s*:\s*"(xmrig|xmr-stak|srbminer|teamredminer|nanominer|lolminer|gminer|nbminer|t-rex|cpuminer|ccminer|bzminer|onezerominer|rigel)`},
	{Name: "ethproxy", Kind: SignatureMining, Regex: `"method"\s*:\s*"eth_submitLogin"`},
}

// MaxSignatureFileSize bounds a signature update.
const MaxSignatureFileSize = 1 << 20

func signatureKind(kind string) (Kind, bool) {
	switch kind {
	case "", SignatureExploit:
		return Exploit, true
	case SignatureMining:
		return Mining, true
	}
	return 0, false
}

// ParseSignatureFile decodes a signature update. Unknown fields and kinds
// are refused, so that a typo does not silently drop a signature.
func ParseSignatureFile(content []byte) ([]SignatureSpec, error) {
	if len(content) > MaxSignatureFileSize {
		return nil, E.New("signature file larger than ", MaxSignatureFileSize, " bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var file SignatureFile
	if err := decoder.Decode(&file); err != nil {
		return nil, E.Cause(err, "decode signature file")
	}
	for index, spec := range file.Signatures {
		if spec.Name == "" {
			return nil, E.New("signature ", index, " has no name")
		}
		if _, known := signatureKind(spec.Kind); !known {
			return nil, E.New("signature ", spec.Name, ": unknown kind ", spec.Kind)
		}
		if spec.Regex == "" && !spec.Disabled {
			return nil, E.New("signature ", spec.Name, " has no regex")
		}
	}
	return file.Signatures, nil
}

// CompileSignatures merges layers of specs, later layers winning by name,
// and compiles those of the enabled kinds in order of first appearance. A
// regex that does not compile is reported and left out; the others still
// apply.
func CompileSignatures(enabled func(Kind) bool, layers ...[]SignatureSpec) ([]Signature, error) {
	var order []string
	merged := make(map[string]SignatureSpec)
	for _, layer := range layers {
		for _, spec := range layer {
			if _, seen := merged[spec.Name]; !seen {
				order = append(order, spec.Name)
			}
			merged[spec.Name] = spec
		}
	}
	signatures := make([]Signature, 0, len(order))
	var errs []error
	for _, name := range order {
		spec := merged[name]
		kind, known := signatureKind(spec.Kind)
		if spec.Disabled || !known || !enabled(kind) {
			continue
		}
		pattern, err := regexp.Compile(spec.Regex)
		if err != nil {
			errs = append(errs, E.Cause(err, "signature ", name))
			continue
		}
		signatures = append(signatures, Signature{Name: name, Kind: kind, Regexp: pattern})
	}
	return signatures, E.Errors(errs...)
}

// MaxSignatureScan is how much of a first payload signatures see: the
// request line and headers of any real request, without scanning every
// plain upload in full.
const MaxSignatureScan = 8 << 10

// MatchSignatures returns the first signature that matches the start of
// payload. A TLS record, which is most of what a node carries, is skipped:
// its content is encrypted, and the server name in a ClientHello is no
// exploit.
func MatchSignatures(signatures []Signature, payload []byte) (Signature, bool) {
	if len(payload) == 0 || payload[0] == 0x16 {
		return Signature{}, false
	}
	payload = payload[:min(len(payload), MaxSignatureScan)]
	for _, signature := range signatures {
		if signature.Regexp.Match(payload) {
			return signature, true
		}
	}
	return Signature{}, false
}
