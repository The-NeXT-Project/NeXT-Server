package nextserver

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/api"
	"github.com/The-NeXT-Project/NeXT-Server/api/serverv1"
	"github.com/The-NeXT-Project/NeXT-Server/common/frontproxy"
	"github.com/The-NeXT-Project/NeXT-Server/common/reporter"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"
	"github.com/The-NeXT-Project/NeXT-Server/proxy"
	"github.com/The-NeXT-Project/NeXT-Server/proxy/inbound"

	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Server runs one panel node: it keeps a node server in sync with the panel
// and routes, accounts and reports everything its users send.
type Server struct {
	ctx      context.Context
	cancel   context.CancelFunc
	logger   log.ContextLogger
	reporter reporter.Reporter
	options  option.ServerOptions
	api      adapter.APIClient

	dialer        N.Dialer
	resolveDomain bool
	connections   *route.ConnectionManager
	users         *userTable
	auditor       *auditor

	pullInterval time.Duration
	pushInterval time.Duration
	loops        sync.WaitGroup

	// Owned by the pull loop once started.
	nodeConfig    *adapter.NodeConfig
	runningConfig *adapter.NodeConfig
	nodeServer    adapter.NodeServer
	userList      []adapter.User

	// Owned by the push loop once started.
	lastPush time.Time
}

func NewServer(ctx context.Context, logger log.ContextLogger, errorReporter reporter.Reporter, options option.ServerOptions) (*Server, error) {
	apiClient, err := api.NewClient(options)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	connections := route.NewConnectionManager(connectionLogger{logger})
	// The default dialer registers its connections here, so Close can end them.
	ctx = service.ContextWith[boxAdapter.ConnectionManager](ctx, connections)
	defaultDialer, err := dialer.NewDefault(ctx, common.PtrValueOrDefault(options.Dialer))
	if err != nil {
		cancel()
		return nil, E.Cause(err, "create dialer")
	}
	server := &Server{
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
		reporter:      errorReporter,
		options:       options,
		api:           apiClient,
		dialer:        defaultDialer,
		resolveDomain: true,
		connections:   connections,
		users:         newUserTable(ctx),
		auditor:       newAuditor(),
		pullInterval:  time.Duration(options.PullInterval),
		pushInterval:  time.Duration(options.PushInterval),
	}
	if options.FrontProxy != nil && options.FrontProxy.Type != "" {
		server.dialer, err = frontproxy.New(defaultDialer, *options.FrontProxy)
		if err != nil {
			cancel()
			return nil, E.Cause(err, "create front proxy")
		}
		server.resolveDomain = options.FrontProxy.ResolveDomain
	}
	if server.pullInterval <= 0 {
		server.pullInterval = constant.DefaultPullInterval
	}
	if server.pushInterval <= 0 {
		server.pushInterval = constant.DefaultPushInterval
	}
	return server, nil
}

// Start fetches the node from the panel and serves it. A panel that cannot be
// reached here is fatal, so a misconfigured node fails loudly.
func (s *Server) Start() error {
	config, err := s.api.FetchNodeConfig(s.ctx)
	if err != nil {
		return E.Cause(err, "fetch node config")
	}
	s.nodeConfig = config
	users, err := s.api.FetchUsers(s.ctx)
	if errors.Is(err, serverv1.ErrNodeUnavailable) {
		s.logger.Warn("panel serves no users: ", err)
		users = []adapter.User{}
	} else if err != nil {
		return E.Cause(err, "fetch users")
	}
	s.applyUsers(users)
	s.pullDetectRules()
	err = s.syncNodeServer()
	if err != nil {
		return err
	}
	s.lastPush = time.Now()
	s.loops.Add(2)
	go s.loop(s.pullInterval, s.pullOnce)
	go s.loop(s.pushInterval, s.pushOnce)
	go func() {
		err := s.api.Heartbeat(s.ctx, 0)
		if err != nil && !E.IsClosedOrCanceled(err) {
			s.logger.Error("heartbeat: ", err)
		}
	}()
	return nil
}

// Close stops the node, ends open connections and reports their last traffic.
func (s *Server) Close() error {
	s.cancel()
	s.loops.Wait()
	var err error
	if s.nodeServer != nil {
		err = s.nodeServer.Close()
	}
	s.connections.CloseAll()
	ctx, cancel := context.WithTimeout(context.Background(), constant.FinalPushTimeout)
	defer cancel()
	if traffic := s.users.collectTraffic(); len(traffic) > 0 {
		if reportErr := s.api.ReportTraffic(ctx, traffic); reportErr != nil {
			err = E.Errors(err, E.Cause(reportErr, "report final traffic"))
		}
	}
	return err
}

func (s *Server) loop(interval time.Duration, run func()) {
	defer s.loops.Done()
	defer s.reporter.Recover()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) logError(message string, err error) {
	if err != nil && !E.IsClosedOrCanceled(err) {
		s.logger.Error(message, ": ", err)
	}
}

func (s *Server) pullOnce() {
	config, err := s.api.FetchNodeConfig(s.ctx)
	s.logError("fetch node config", err)
	if config != nil {
		s.nodeConfig = config
	}
	err = s.syncNodeServer()
	s.logError("update node server", err)
	users, err := s.api.FetchUsers(s.ctx)
	if errors.Is(err, serverv1.ErrNodeUnavailable) {
		if len(s.userList) > 0 {
			s.logger.Warn("panel stopped serving users: ", err)
		}
		users = []adapter.User{}
	} else {
		s.logError("fetch users", err)
	}
	if users != nil {
		s.applyUsers(users)
	}
	s.pullDetectRules()
}

func (s *Server) pullDetectRules() {
	rules, err := s.api.FetchDetectRules(s.ctx)
	// Invalid rules come with the valid ones, which still apply.
	s.logError("fetch detect rules", err)
	if rules != nil {
		s.auditor.setRules(rules)
	}
}

// syncNodeServer brings the running node server in line with the panel. The
// listener is only rebuilt when something it was built from changed; a failed
// rebuild is retried on the next pull.
func (s *Server) syncNodeServer() error {
	config := s.nodeConfig
	if s.runningConfig != nil && config.SpeedLimit != s.runningConfig.SpeedLimit {
		s.users.update(s.userList, config.SpeedLimit)
	}
	if s.nodeServer != nil && sameListener(config, s.runningConfig) {
		s.runningConfig = config
		return nil
	}
	if s.nodeServer != nil {
		err := s.nodeServer.Close()
		s.logError("close node server", err)
		s.nodeServer = nil
		s.runningConfig = nil
	}
	if config.TLS != nil && config.TLS.Insecure {
		s.logger.Warn("no certificate configured, serving a self-signed one; clients must set allow_insecure")
	}
	nodeServer, err := proxy.New(inbound.NodeOptions{
		Context: s.ctx,
		Logger:  connectionLogger{s.logger},
		Router:  s,
		Config:  config,
		Server:  s.options,
	})
	if err != nil {
		return E.Cause(err, "create ", config.Type, " server")
	}
	err = nodeServer.UpdateUsers(s.userList)
	if err != nil {
		nodeServer.Close()
		return E.Cause(err, "update users")
	}
	err = nodeServer.Start()
	if err != nil {
		nodeServer.Close()
		return E.Cause(err, "start ", config.Type, " server")
	}
	s.nodeServer = nodeServer
	s.runningConfig = config
	s.logger.Info(config.Type, " server started on port ", config.ListenPort, " with ", len(s.userList), " users")
	return nil
}

// sameListener compares configs except the speed limit, which applies
// without a restart.
func sameListener(a, b *adapter.NodeConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	left, right := *a, *b
	left.SpeedLimit, right.SpeedLimit = 0, 0
	return reflect.DeepEqual(left, right)
}

func (s *Server) applyUsers(users []adapter.User) {
	// The table first: a removed user must stop routing before the node
	// server stops authenticating them, and a new one must be routable as
	// soon as it authenticates.
	s.users.update(users, s.nodeConfig.SpeedLimit)
	s.userList = users
	if s.nodeServer == nil {
		return
	}
	err := s.nodeServer.UpdateUsers(users)
	if err != nil {
		s.logError("update users", err)
		return
	}
	s.logger.Info("serving ", len(users), " users")
}

func (s *Server) pushOnce() {
	since := s.lastPush
	s.lastPush = time.Now()

	var online []adapter.UserOnline
	onlineUsers := 0
	for id, user := range s.users.all() {
		addresses := user.onlineIPs(since)
		if len(addresses) == 0 {
			continue
		}
		onlineUsers++
		for _, address := range addresses {
			online = append(online, adapter.UserOnline{UserID: id, IP: M.SocksaddrFrom(address, 0).AddrString()})
		}
	}
	s.logError("heartbeat", s.api.Heartbeat(s.ctx, onlineUsers))

	if traffic := s.users.collectTraffic(); len(traffic) > 0 {
		err := s.api.ReportTraffic(s.ctx, traffic)
		if err != nil {
			s.users.restoreTraffic(traffic)
			s.logError("report traffic", err)
		}
	}
	if len(online) > 0 {
		s.logError("report online users", s.api.ReportOnline(s.ctx, online))
	}
	if logs := s.auditor.collect(); len(logs) > 0 {
		err := s.api.ReportDetectLogs(s.ctx, logs)
		if err != nil {
			s.auditor.restore(logs)
			s.logError("report detect logs", err)
		}
	}
}
