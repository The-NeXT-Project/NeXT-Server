package constant

import "time"

const (
	DefaultPullInterval = 60 * time.Second
	DefaultPushInterval = 60 * time.Second
	// FinalPushTimeout bounds the traffic report sent while shutting down.
	FinalPushTimeout = 10 * time.Second
)
