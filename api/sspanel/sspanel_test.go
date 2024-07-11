package sspanel_test

import (
	"fmt"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/api"
	"github.com/The-NeXT-Project/NeXT-Server/api/sspanel"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   3,
		NodeType: "vmess",
	}

	client := sspanel.New(apiConfig)

	return client
}

func TestGetVmessNodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   3,
		NodeType: "vmess",
	}

	client := sspanel.New(apiConfig)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}

	t.Log(nodeInfo)
}

func TestGetSSNodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   64,
		NodeType: "shadowsocks",
	}

	client := sspanel.New(apiConfig)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}

	t.Log(nodeInfo)
}

func TestGetSS2022NodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   64,
		NodeType: "shadowsocks2022",
	}

	client := sspanel.New(apiConfig)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}

	t.Log(nodeInfo)
}

func TestGetTrojanNodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   72,
		NodeType: "trojan",
	}

	client := sspanel.New(apiConfig)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}

	t.Log(nodeInfo)
}

func TestGetSSInfo(t *testing.T) {
	client := CreateClient()

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(userList)
}

func TestReportReportNodeOnlineUsers(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	onlineUserList := make([]api.OnlineUser, len(*userList))
	for i, userInfo := range *userList {
		onlineUserList[i] = api.OnlineUser{
			UID: userInfo.UID,
			IP:  fmt.Sprintf("1.1.1.%d", i),
		}
	}
	// client.Debug()
	err = client.ReportNodeOnlineUsers(&onlineUserList)
	if err != nil {
		t.Error(err)
	}
}

func TestReportReportUserTraffic(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   114514,
			Download: 114514,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	client := CreateClient()

	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

func TestReportIllegal(t *testing.T) {
	client := CreateClient()

	detectResult := []api.DetectResult{
		{UID: 1, RuleID: 2},
		{UID: 1, RuleID: 3},
	}
	client.Debug()
	err := client.ReportIllegal(&detectResult)
	if err != nil {
		t.Error(err)
	}
}
