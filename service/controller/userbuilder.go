package controller

import (
	"fmt"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"strings"

	"github.com/SSPanel-UIM/UIM-Server/api"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
)

func (c *Controller) buildVmessUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       user.UUID,
			Security: "auto",
		}

		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}

	return users
}

func (c *Controller) buildTrojanUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		trojanAccount := &trojan.Account{
			Password: user.UUID,
		}

		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}

	return users
}

func (c *Controller) buildSSUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		users[i] = &protocol.User{
			Level: 0,
			Email: c.buildUserTag(&user),
			Account: serial.ToTypedMessage(&shadowsocks.Account{
				Password:   user.Passwd,
				CipherType: cipherFromString(user.Method),
			}),
		}
	}

	return users
}

func (c *Controller) buildSS2022User(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		email := c.buildUserTag(&user)

		users[i] = &protocol.User{
			Level: 0,
			Email: email,
			Account: serial.ToTypedMessage(&shadowsocks_2022.User{
				Key:   user.Passwd,
				Email: email,
				Level: 0,
			}),
		}
	}

	return users
}

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func (c *Controller) buildUserTag(user *api.UserInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)
}
