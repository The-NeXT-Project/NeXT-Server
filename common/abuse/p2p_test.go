package abuse

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// eDonkeyLogin builds a client's login to an eDonkey server.
func eDonkeyLogin(tags int) []byte {
	body := []byte{eDonkeyHelloOp}
	body = append(body, bytes.Repeat([]byte{0xab}, 16)...) // user hash
	body = append(body, 0, 0, 0, 0, 0x36, 0x12)            // client ID, port 4662
	body = binary.LittleEndian.AppendUint32(body, uint32(tags))
	for i := 0; i < tags; i++ {
		body = append(body, 0x02, 0x01, 0x00, 0x01, 0x04, 0x00, 'n', 'a', 'm', 'e')
	}
	packet := []byte{eDonkeyProtocol}
	packet = binary.LittleEndian.AppendUint32(packet, uint32(len(body)))
	return append(packet, body...)
}

func TestP2PStream(t *testing.T) {
	login := eDonkeyLogin(2)
	cases := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"announce", []byte("GET /announce?info_hash=%12%34&peer_id=-qB4650-abc&port=6881 HTTP/1.1\r\nHost: tracker.example\r\n\r\n"), BitTorrent},
		{"scrape", []byte("GET /scrape?info_hash=%12%34 HTTP/1.0\r\n\r\n"), BitTorrent},
		{"info_hash later in the query", []byte("GET /a?port=1&info_hash=%12 HTTP/1.1\r\n"), BitTorrent},
		// Cut off before the end of the line, as a first payload may be.
		{"cut off announce", []byte("GET /announce?info_hash=%12%34&peer_id"), BitTorrent},
		{"eDonkey login", login, EDonkey},
		{"eDonkey login followed by more", append(append([]byte(nil), login...), 0xE3, 1, 0, 0, 0, 0x14), EDonkey},
		{"info_hash in a header", []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: ?info_hash=\r\n\r\n"), ""},
		{"info_hash as a search term", []byte("GET /search?q=info_hash HTTP/1.1\r\n\r\n"), ""},
		{"POST", []byte("POST /announce?info_hash=%12 HTTP/1.1\r\n\r\n"), ""},
		{"eDonkey cut off", login[:20], ""},
		{"eDonkey length past the payload", append([]byte{0xE3, 0xff, 0, 0, 0}, login[5:]...), ""},
		{"TLS", []byte("\x16\x03\x01\x02\x00"), ""},
		{"empty", nil, ""},
	}
	for _, testCase := range cases {
		protocol, found := P2PStream(testCase.payload)
		if protocol != testCase.want || found != (testCase.want != "") {
			t.Errorf("%s: P2PStream = %q, %v", testCase.name, protocol, found)
		}
	}
}

func TestP2PPacket(t *testing.T) {
	connect := make([]byte, 16)
	binary.BigEndian.PutUint64(connect, udpTrackerProtocolID)
	binary.BigEndian.PutUint32(connect[12:], 0x1234)
	announce := append([]byte(nil), connect...)
	binary.BigEndian.PutUint32(announce[8:], 1)
	framedLikeBencode := make([]byte, 1200)
	framedLikeBencode[0] = 'd'
	framedLikeBencode[len(framedLikeBencode)-1] = 'e'

	kadHello := append([]byte{kadProtocol, kadHelloReq}, bytes.Repeat([]byte{0x5a}, 16)...)
	kadHello = append(kadHello, 0x36, 0x12, 0x08, 0x01, 0x03, 0x01, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00)
	kadRequest := append([]byte{kadProtocol, kadReq, 0x02}, bytes.Repeat([]byte{0x11}, 32)...)
	// QUIC v1 Handshake packets can begin with 0xE4 and continue with the
	// version, 0x00000001.
	quicHandshake := append([]byte{0xE4, 0x00, 0x00, 0x00, 0x01, 0x08}, bytes.Repeat([]byte{0x77}, 1194)...)
	quicHandshake2 := append([]byte{0xE4, 0x6b, 0x33, 0x43, 0xcf, 0x08}, bytes.Repeat([]byte{0x77}, 60)...)

	cases := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"DHT ping", []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"), BitTorrent},
		{"DHT get_peers", []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"), BitTorrent},
		{"DHT response with ip", []byte("d2:ip6:\x01\x02\x03\x04\x1a\xe11:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"), BitTorrent},
		{"DHT error", []byte("d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"), BitTorrent},
		{"UDP tracker connect", connect, BitTorrent},
		{"Kad bootstrap", []byte{kadProtocol, kadBootstrapReq}, Kad},
		{"Kad ping", []byte{kadProtocol, kadPing}, Kad},
		{"Kad hello", kadHello, Kad},
		{"Kad request", kadRequest, Kad},
		// Later tracker messages carry a random connection ID instead.
		{"UDP tracker announce", announce, ""},
		{"bencode that is not KRPC", []byte("d4:spaml1:a1:bee"), ""},
		{"bencode with an unknown y", []byte("d1:t2:aa1:y1:xe"), ""},
		{"random data framed like bencode", framedLikeBencode, ""},
		{"Kad request of the wrong length", append(append([]byte(nil), kadRequest...), 0), ""},
		{"Kad hello with too many tags", append(append([]byte(nil), kadHello[:21]...), 0x40), ""},
		{"QUIC v1 Handshake", quicHandshake, ""},
		{"QUIC v2 Handshake", quicHandshake2, ""},
		{"empty", nil, ""},
	}
	for _, testCase := range cases {
		protocol, found := P2PPacket(testCase.payload)
		if protocol != testCase.want || found != (testCase.want != "") {
			t.Errorf("%s: P2PPacket = %q, %v", testCase.name, protocol, found)
		}
	}
}
