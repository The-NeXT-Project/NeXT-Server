//go:build !with_sentry

package reporter

import (
	"github.com/The-NeXT-Project/NeXT-Server/option"

	E "github.com/sagernet/sing/common/exceptions"
)

func New(options *option.SentryOptions) (Reporter, error) {
	if options != nil {
		return nil, E.New("sentry is not included in this build, rebuild with -tags with_sentry")
	}
	return nopReporter{}, nil
}
