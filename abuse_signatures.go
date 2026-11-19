package nextserver

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/The-NeXT-Project/NeXT-Server/common/abuse"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// signatureSet holds the exploit and mining signatures connections are
// matched against: the built-in ones, then those of the signature file and
// the signature URL, a later one replacing an earlier one of the same name.
// Connections read it lock-free; refresh belongs to the pull loop.
type signatureSet struct {
	compiled atomic.Pointer[[]abuse.Signature]
	enabled  func(abuse.Kind) bool

	path     string
	url      string
	client   *http.Client
	file     signatureSource
	remote   signatureSource
	lastLog  string
	lastErrs string
}

// signatureSource is what one source last gave. version is the file's size
// and modification time, or the URL's ETag: a source is read again only
// when it changes, also after it failed, so a broken update is reported once.
type signatureSource struct {
	version string
	specs   []abuse.SignatureSpec
}

func newSignatureSet(options option.AbuseSignaturesOptions, exploits, mining bool) (*signatureSet, error) {
	if options.URL != "" {
		parsed, err := url.Parse(options.URL)
		if err != nil {
			return nil, E.Cause(err, "abuse.signatures.url")
		}
		// Signatures decide what users may send; nobody on the way may change them.
		if parsed.Scheme != "https" {
			return nil, E.New("abuse.signatures.url must be https")
		}
	}
	set := &signatureSet{
		enabled: func(kind abuse.Kind) bool {
			return (kind == abuse.Exploit && exploits) || (kind == abuse.Mining && mining)
		},
		path:   options.Path,
		url:    options.URL,
		client: &http.Client{Timeout: constant.SignatureFetchTimeout},
	}
	signatures, err := abuse.CompileSignatures(set.enabled, abuse.BuiltinSignatures)
	if err != nil {
		return nil, E.Cause(err, "built-in signatures")
	}
	set.compiled.Store(&signatures)
	return set, nil
}

func (s *signatureSet) current() []abuse.Signature {
	return *s.compiled.Load()
}

// refresh reads the sources again and recompiles when one changed. A source
// that fails keeps the signatures it gave last. It returns a summary when
// the set changed, and the errors, each of which is new since the last call.
func (s *signatureSet) refresh(ctx context.Context) (string, error) {
	var errs []error
	changed := false
	if s.path != "" {
		fileChanged, err := s.refreshFile()
		changed = changed || fileChanged
		if err != nil {
			errs = append(errs, E.Cause(err, "signature file ", s.path))
		}
	}
	if s.url != "" {
		urlChanged, err := s.refreshURL(ctx)
		changed = changed || urlChanged
		if err != nil {
			errs = append(errs, E.Cause(err, "signature URL"))
		}
	}
	var summary string
	if changed {
		signatures, err := abuse.CompileSignatures(s.enabled, abuse.BuiltinSignatures, s.file.specs, s.remote.specs)
		if err != nil {
			errs = append(errs, err)
		}
		s.compiled.Store(&signatures)
		var exploits, mining int
		for _, signature := range signatures {
			if signature.Kind == abuse.Mining {
				mining++
			} else {
				exploits++
			}
		}
		summary = F.ToString(exploits, " exploit and ", mining, " mining signatures active (", len(s.file.specs), " from the file, ", len(s.remote.specs), " from the URL)")
		if summary == s.lastLog {
			summary = ""
		} else {
			s.lastLog = summary
		}
	}
	err := E.Errors(errs...)
	// A source that keeps failing the same way is reported once.
	if err != nil && err.Error() == s.lastErrs {
		return summary, nil
	}
	if err != nil {
		s.lastErrs = err.Error()
	} else {
		s.lastErrs = ""
	}
	return summary, err
}

func (s *signatureSet) refreshFile() (bool, error) {
	info, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		// Removing the file removes its signatures.
		changed := s.file.version != "missing"
		s.file = signatureSource{version: "missing"}
		return changed, err
	}
	if err != nil {
		return false, err
	}
	version := F.ToString(info.Size(), " ", info.ModTime().UnixNano())
	if version == s.file.version {
		return false, nil
	}
	s.file.version = version
	content, err := readLimited(func() (io.ReadCloser, error) { return os.Open(s.path) })
	if err != nil {
		return false, err
	}
	specs, err := abuse.ParseSignatureFile(content)
	if err != nil {
		return false, err
	}
	s.file.specs = specs
	return true, nil
}

func (s *signatureSet) refreshURL(ctx context.Context) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return false, err
	}
	if s.remote.version != "" {
		request.Header.Set("If-None-Match", s.remote.version)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	default:
		return false, E.New("HTTP ", response.Status)
	}
	s.remote.version = response.Header.Get("ETag")
	content, err := readLimited(func() (io.ReadCloser, error) { return response.Body, nil })
	if err != nil {
		return false, err
	}
	specs, err := abuse.ParseSignatureFile(content)
	if err != nil {
		return false, err
	}
	s.remote.specs = specs
	return true, nil
}

func readLimited(open func() (io.ReadCloser, error)) ([]byte, error) {
	reader, err := open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, abuse.MaxSignatureFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) > abuse.MaxSignatureFileSize {
		return nil, E.New("larger than ", abuse.MaxSignatureFileSize, " bytes")
	}
	return content, nil
}

// refreshSignatures runs on every pull. Failures are logged at warn: the
// node keeps the last good signatures, and the built-in ones always apply.
func (g *abuseGuard) refreshSignatures(ctx context.Context) {
	if g.signatures == nil || (g.signatures.path == "" && g.signatures.url == "") {
		return
	}
	summary, err := g.signatures.refresh(ctx)
	if summary != "" {
		g.logger.Info(summary)
	}
	if err != nil && !E.IsClosedOrCanceled(err) {
		g.logger.Warn("update abuse signatures, keeping the last good ones: ", err)
	}
}
