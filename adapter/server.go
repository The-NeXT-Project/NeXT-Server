package adapter

import (
	boxAdapter "github.com/sagernet/sing-box/adapter"
)

// NodeServer is one protocol listener. Users are swapped in place so that a
// user list change never drops the listener or other users' sessions.
type NodeServer interface {
	Start() error
	Close() error
	UpdateUsers(users []User) error
}

// Router receives every proxied connection from a node server. The context
// must carry the panel user ID, set with auth.ContextWithUser[int].
type Router interface {
	boxAdapter.ConnectionRouterEx
}
