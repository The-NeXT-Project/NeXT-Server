// Package abuse recognizes BitTorrent traffic and follows each user's
// connections for port scans and floods.
package abuse

import (
	"bytes"
	"encoding/binary"
)

// BitTorrentRequest reports whether the first payload of a TCP connection is
// an HTTP tracker announce or scrape. sing-box's sniffer recognizes the peer
// handshake itself; MSE-encrypted peers and HTTPS trackers look like any other
// encrypted stream and pass.
func BitTorrentRequest(payload []byte) bool {
	line, found := bytes.CutPrefix(payload, []byte("GET "))
	if !found {
		return false
	}
	if end := bytes.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	return bytes.Contains(line, []byte("?info_hash=")) || bytes.Contains(line, []byte("&info_hash="))
}

// BitTorrentPacket reports whether a UDP payload is a DHT message or a UDP
// tracker connect request. It is cheap enough for every packet of a session:
// most packets fail on the first byte. uTP is only recognized on the first
// packet, by sing-box's sniffer, because a QUIC short header can look like it.
func BitTorrentPacket(payload []byte) bool {
	return dhtMessage(payload) || udpTrackerConnect(payload)
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
