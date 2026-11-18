package abuse

import (
	"encoding/binary"
	"testing"
)

func TestBitTorrentRequest(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{"GET /announce?info_hash=%12%34&peer_id=-qB4650-abc&port=6881 HTTP/1.1\r\nHost: tracker.example\r\n\r\n", true},
		{"GET /scrape?info_hash=%12%34 HTTP/1.0\r\n\r\n", true},
		{"GET /a?port=1&info_hash=%12 HTTP/1.1\r\n", true},
		// Cut off before the end of the line, as a first payload may be.
		{"GET /announce?info_hash=%12%34&peer_id", true},
		{"GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: ?info_hash=\r\n\r\n", false},
		{"GET /search?q=info_hash HTTP/1.1\r\n\r\n", false},
		{"POST /announce?info_hash=%12 HTTP/1.1\r\n\r\n", false},
		{"\x16\x03\x01\x02\x00", false},
		{"", false},
	}
	for _, testCase := range cases {
		if got := BitTorrentRequest([]byte(testCase.payload)); got != testCase.want {
			t.Errorf("BitTorrentRequest(%q) = %v", testCase.payload, got)
		}
	}
}

func TestBitTorrentPacket(t *testing.T) {
	connect := make([]byte, 16)
	binary.BigEndian.PutUint64(connect, udpTrackerProtocolID)
	binary.BigEndian.PutUint32(connect[12:], 0x1234)
	announce := append([]byte(nil), connect...)
	binary.BigEndian.PutUint32(announce[8:], 1)
	quicShort := make([]byte, 1200)
	quicShort[0] = 'd'
	quicShort[len(quicShort)-1] = 'e'

	cases := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"ping query", []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"), true},
		{"get_peers query", []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"), true},
		{"response with ip", []byte("d2:ip6:\x01\x02\x03\x04\x1a\xe11:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"), true},
		{"error", []byte("d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"), true},
		{"udp tracker connect", connect, true},
		// Later tracker messages carry a random connection ID instead.
		{"udp tracker announce", announce, false},
		{"bencode that is not KRPC", []byte("d4:spaml1:a1:bee"), false},
		{"bencode with an unknown y", []byte("d1:t2:aa1:y1:xe"), false},
		{"random data framed like bencode", quicShort, false},
		{"empty", nil, false},
	}
	for _, testCase := range cases {
		if got := BitTorrentPacket(testCase.payload); got != testCase.want {
			t.Errorf("%s: BitTorrentPacket = %v", testCase.name, got)
		}
	}
}
