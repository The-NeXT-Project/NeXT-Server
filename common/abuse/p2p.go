// Package abuse recognizes P2P file sharing and follows each user's
// connections for port scans, floods and brute force.
package abuse

import (
	"bytes"
	"encoding/binary"
)

// P2P protocol names, for logs.
const (
	BitTorrent = "BitTorrent"
	EDonkey    = "eDonkey"
	Kad        = "Kad"
)

// P2PStream reports which P2P protocol the first payload of a TCP connection
// opens, beyond the BitTorrent peer handshake that sing-box's sniffer finds:
// an HTTP tracker announce or scrape, or an eDonkey hello. Encrypted
// BitTorrent (MSE), obfuscated eDonkey and HTTPS trackers look like any other
// encrypted stream and pass.
func P2PStream(payload []byte) (string, bool) {
	switch {
	case trackerRequest(payload):
		return BitTorrent, true
	case eDonkeyHello(payload):
		return EDonkey, true
	}
	return "", false
}

// P2PPacket reports which P2P protocol a UDP payload belongs to: a DHT
// message, a UDP tracker connect request, or a Kad message. It is cheap
// enough for every packet of a session: most packets fail on the first byte.
// uTP is only recognized on the first packet, by sing-box's sniffer, because
// a QUIC short header can look like it.
func P2PPacket(payload []byte) (string, bool) {
	switch {
	case dhtMessage(payload), udpTrackerConnect(payload):
		return BitTorrent, true
	case kadMessage(payload):
		return Kad, true
	}
	return "", false
}

func trackerRequest(payload []byte) bool {
	line, found := bytes.CutPrefix(payload, []byte("GET "))
	if !found {
		return false
	}
	if end := bytes.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	return bytes.Contains(line, []byte("?info_hash=")) || bytes.Contains(line, []byte("&info_hash="))
}

// dhtMessage recognizes a KRPC message (BEP 5): a bencoded dictionary with a
// transaction ID "t" and a type "y" of query, response or error.
func dhtMessage(payload []byte) bool {
	if len(payload) < 12 || payload[0] != 'd' || payload[len(payload)-1] != 'e' {
		return false
	}
	index := bytes.Index(payload, []byte("1:y1:"))
	if index < 0 || index+5 >= len(payload) {
		return false
	}
	switch payload[index+5] {
	case 'q', 'r', 'e':
		return bytes.Contains(payload, []byte("1:t"))
	}
	return false
}

const udpTrackerProtocolID = 0x41727101980

// udpTrackerConnect recognizes the connect request of the UDP tracker
// protocol (BEP 15), the only one of its messages with a fixed header.
func udpTrackerConnect(payload []byte) bool {
	return len(payload) >= 16 &&
		binary.BigEndian.Uint64(payload) == udpTrackerProtocolID &&
		binary.BigEndian.Uint32(payload[8:]) == 0
}

const (
	eDonkeyProtocol = 0xE3
	eDonkeyHelloOp  = 0x01
	// eDonkeyMinHello is the opcode, a 16-byte user hash, a client ID, a
	// port and a tag count: the server login, the shorter of the two hellos.
	eDonkeyMinHello = 1 + 16 + 4 + 2 + 4
)

// eDonkeyHello recognizes the first message of an unobfuscated eDonkey
// connection, to a server (login) or to another client (hello): protocol
// 0xE3, a little-endian length that the payload holds, and opcode 0x01.
func eDonkeyHello(payload []byte) bool {
	if len(payload) < 5+eDonkeyMinHello || payload[0] != eDonkeyProtocol || payload[5] != eDonkeyHelloOp {
		return false
	}
	size := binary.LittleEndian.Uint32(payload[1:])
	return size >= eDonkeyMinHello && size <= uint32(len(payload)-5)
}

const (
	kadProtocol      = 0xE4
	kadBootstrapReq  = 0x01
	kadHelloReq      = 0x11
	kadHelloRes      = 0x19
	kadReq           = 0x21
	kadPing          = 0x60
	kadHelloMinSize  = 2 + 16 + 2 + 1 + 1
	kadHelloMaxTags  = 8
	kadRequestLength = 2 + 1 + 16 + 16
)

// kadMessage recognizes Kademlia 2 messages of eMule's Kad network by their
// exact shape. 0xE4 is also a valid first byte of a QUIC Handshake packet,
// whose second byte is a version byte, so only opcodes whose length is fixed
// or bounded are matched, never a bare prefix.
func kadMessage(payload []byte) bool {
	if len(payload) < 2 || payload[0] != kadProtocol {
		return false
	}
	switch payload[1] {
	case kadBootstrapReq, kadPing:
		return len(payload) == 2
	case kadReq:
		return len(payload) == kadRequestLength
	case kadHelloReq, kadHelloRes:
		return len(payload) >= kadHelloMinSize && payload[kadHelloMinSize-1] <= kadHelloMaxTags
	}
	return false
}
