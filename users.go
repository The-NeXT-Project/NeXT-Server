package nextserver

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/common/limit"
)

// userState is the accounting for one panel user. Connections hold on to the
// state they started with, so traffic is never counted against a fresh object.
type userState struct {
	id int
	// ctx is canceled when the panel stops serving the user, which closes
	// their open connections.
	ctx    context.Context
	cancel context.CancelFunc

	upload   atomic.Int64
	download atomic.Int64
	// limiter is nil when neither the user nor the node has a speed limit.
	limiter atomic.Pointer[limit.Limiter]

	access sync.Mutex
	ips    map[netip.Addr]*ipActivity
	active int
}

type ipActivity struct {
	active   int
	lastSeen time.Time
}

func newUserState(ctx context.Context, id int) *userState {
	state := &userState{id: id, ips: make(map[netip.Addr]*ipActivity)}
	state.ctx, state.cancel = context.WithCancel(ctx)
	return state
}

func (u *userState) setSpeedLimit(bytesPerSecond uint64) {
	current := u.limiter.Load()
	switch {
	case bytesPerSecond == 0:
		u.limiter.Store(nil)
	case current == nil:
		u.limiter.Store(limit.New(bytesPerSecond))
	default:
		current.SetLimit(bytesPerSecond)
	}
}

// open records a connection from address and returns the function that
// records its end.
func (u *userState) open(address netip.Addr) func() {
	address = address.Unmap()
	u.access.Lock()
	activity := u.ips[address]
	if activity == nil {
		activity = &ipActivity{}
		u.ips[address] = activity
	}
	activity.active++
	activity.lastSeen = time.Now()
	u.active++
	u.access.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			u.access.Lock()
			activity.active--
			activity.lastSeen = time.Now()
			u.active--
			u.access.Unlock()
		})
	}
}

// onlineIPs returns the addresses connected now or since `since`, and forgets
// the others.
func (u *userState) onlineIPs(since time.Time) []netip.Addr {
	u.access.Lock()
	defer u.access.Unlock()
	var addresses []netip.Addr
	for address, activity := range u.ips {
		if activity.active > 0 || !activity.lastSeen.Before(since) {
			addresses = append(addresses, address)
		} else {
			delete(u.ips, address)
		}
	}
	return addresses
}

func (u *userState) activeConnections() int {
	u.access.Lock()
	defer u.access.Unlock()
	return u.active
}

// userTable maps panel user IDs to their state. Lookups are lock-free; updates
// come only from the pull loop.
type userTable struct {
	ctx     context.Context
	current atomic.Pointer[map[int]*userState]

	access sync.Mutex
	// retired users are no longer served but may still have unreported
	// traffic from connections that were closing.
	retired []*userState
}

func newUserTable(ctx context.Context) *userTable {
	table := &userTable{ctx: ctx}
	empty := make(map[int]*userState)
	table.current.Store(&empty)
	return table
}

func (t *userTable) get(id int) *userState {
	return (*t.current.Load())[id]
}

func (t *userTable) all() map[int]*userState {
	return *t.current.Load()
}

// update applies a new user list. Users that stay keep their counters, and
// users that leave have their connections closed.
func (t *userTable) update(users []adapter.User, nodeSpeedLimit uint64) {
	previous := *t.current.Load()
	next := make(map[int]*userState, len(users))
	for _, user := range users {
		state := previous[user.ID]
		if state == nil {
			state = newUserState(t.ctx, user.ID)
		}
		state.setSpeedLimit(effectiveLimit(nodeSpeedLimit, user.SpeedLimit))
		next[user.ID] = state
	}
	t.current.Store(&next)
	t.access.Lock()
	for id, state := range previous {
		if _, kept := next[id]; !kept {
			state.cancel()
			t.retired = append(t.retired, state)
		}
	}
	t.access.Unlock()
}

// collectTraffic resets and returns every user's counters, then drops
// retired users that have nothing left to report.
func (t *userTable) collectTraffic() []adapter.UserTraffic {
	var items []adapter.UserTraffic
	collect := func(state *userState) bool {
		upload, download := state.upload.Swap(0), state.download.Swap(0)
		if upload == 0 && download == 0 {
			return false
		}
		items = append(items, adapter.UserTraffic{UserID: state.id, Upload: upload, Download: download})
		return true
	}
	for _, state := range t.all() {
		collect(state)
	}
	t.access.Lock()
	retired := t.retired[:0]
	for _, state := range t.retired {
		if collect(state) || state.activeConnections() > 0 {
			retired = append(retired, state)
		}
	}
	clear(t.retired[len(retired):])
	t.retired = retired
	t.access.Unlock()
	return items
}

// restoreTraffic puts back counts that failed to reach the panel.
func (t *userTable) restoreTraffic(items []adapter.UserTraffic) {
	for _, item := range items {
		state := t.get(item.UserID)
		if state == nil {
			t.access.Lock()
			for _, retired := range t.retired {
				if retired.id == item.UserID {
					state = retired
					break
				}
			}
			if state == nil {
				// Already dropped from the retired list; keep it reportable.
				state = newUserState(t.ctx, item.UserID)
				state.cancel()
				t.retired = append(t.retired, state)
			}
			t.access.Unlock()
		}
		state.upload.Add(item.Upload)
		state.download.Add(item.Download)
	}
}

// effectiveLimit applies the stricter of two limits, where 0 means unlimited.
func effectiveLimit(a, b uint64) uint64 {
	if a == 0 || (b != 0 && b < a) {
		return b
	}
	return a
}
