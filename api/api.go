package api

// API is the interface for different panel's api.
type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetUserList() (userList *[]UserInfo, err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	ReportIllegal(detectResultList *[]DetectResult) (err error)
	Debug()
}
