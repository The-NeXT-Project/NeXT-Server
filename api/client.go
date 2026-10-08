package api

import (
	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/api/serverv1"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	E "github.com/sagernet/sing/common/exceptions"
)

func NewClient(options option.ServerOptions) (adapter.APIClient, error) {
	switch options.API {
	case "", option.APITypeServerV1:
		return serverv1.NewClient(options)
	default:
		return nil, E.New("unknown api: ", options.API)
	}
}
