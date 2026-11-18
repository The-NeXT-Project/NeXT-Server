# NeXT-Server

The node backend for [NeXT-Panel](https://github.com/The-NeXT-Project/NeXT-Panel), built on [sing-box](https://github.com/SagerNet/sing-box).

It fetches its node settings and users from the panel's Server API V1, serves them, and reports traffic, online IPs and detect rule hits back. User list changes apply in place, without restarting the listener or dropping other users' connections.

Upgrading from v0 (the Xray-based server, on the `v0` branch)? See the [changelog](CHANGELOG.md) for what changed and how to migrate a node.

## Supported node types

| Panel type | `sort` | Users authenticate with |
| --- | --- | --- |
| Shadowsocks 2022 | 1 | `passwd` (the user key derived by the panel) |
| TUIC v5 | 2 | `uuid` + `passwd` |
| Hysteria2 | 4 | `passwd` |
| AnyTLS | 5 | `passwd` |
| VMess | 11 | `uuid` |
| Trojan | 14 | `uuid` |

Snell (3) and NaïveProxy (6) are not supported yet. VMess and Trojan accept the `ws`, `http`/`h2`, `httpupgrade`, `grpc` and `quic` transports.

The node listens on `offset_port_node`, falling back to `offset_port_user`, then 443. Shadowsocks 2022 nodes need `server_key` in their custom config.

## Configuration

`next-server -c /etc/next-server/config.json`. The file is JSON and may contain comments. Unknown fields are rejected.

```jsonc
{
  "log": { "level": "info" },        // sing-box log options
  "servers": [
    {
      "url": "https://panel.example.com",
      "key": "<node communication key>",  // Node -> communication key in the panel

      "timeout": "30s",              // panel request timeout
      "pull_interval": "60s",        // node settings, users and detect rules
      "push_interval": "60s",        // heartbeat, traffic, online IPs, detect logs

      "listen": "::",                // plus any sing-box listen field, e.g. tcp_fast_open
      "proxy_protocol": false,       // accept PROXY protocol v1/v2 headers on TCP
      "proxy_protocol_trusted": [],  // CIDRs allowed to send them; empty trusts everyone

      "tls": {},                     // certificate source, see below
      "multiplex": { "enabled": true },  // sing-mux for VMess, Trojan and Shadowsocks
      "dialer": {},                  // sing-box dialer options for outbound traffic
      "front_proxy": null,           // { "type": "socks5"|"socks4"|"socks4a"|"http", "server": "host:port", ... }
      "allow_private_destinations": false, // let users reach the node itself and its private networks
      "abuse": {}                    // BitTorrent, spam, port scan and flood checks, see below
    }
  ]
}
```

`servers` may list several nodes; each runs independently.

### TLS certificates

TLS node types (TUIC, Hysteria2, AnyTLS, Trojan, and VMess with `"security": "tls"`) take their certificate from `tls`, which accepts the sing-box inbound TLS fields:

- `certificate_path` and `key_path`: a certificate on disk, reloaded when the files change.
- `acme`: certificates from Let's Encrypt. Leave `domain` empty to use the node's `host` from the panel (or its address, if that is a domain). A client asking for a name the certificates do not cover gets the one for `default_server_name`, or the first `domain`, so a node behind a CDN (whose panel address is the CDN's name) keeps a renewed certificate: set `domain` to the node's own name.
- Nothing: a self-signed certificate is generated, and clients connect only with `allow_insecure` set on the node.

The panel's `host` becomes the server name.

### Abuse checks

Besides the panel's detect rules, every node refuses common abuse on its own. All checks are on by default; `abuse` only needs to be set to change them:

```jsonc
"abuse": {
  "disabled": false,                  // true turns every check off
  "ban_duration": "10m",              // how long a scanning, flooding or brute-forcing user is refused on this node
  "p2p":           { "disabled": false, "rule_id": 0 },
  "blocked_ports": { "disabled": false, "rule_id": 0, "ports": [25, 135, 137, 138, 139, 445] },
  "port_scan":     { "disabled": false, "rule_id": 0, "window": "1m",  "failed_destinations": 60, "ports_per_host": 100 },
  "flood":         { "disabled": false, "rule_id": 0, "window": "10s", "connections": 1000, "connections_per_destination": 200 },
  "brute_force":   { "disabled": false, "rule_id": 0, "window": "1m",  "hosts": 30, "connections_per_destination": 120,
                     "ports": [21, 22, 23, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017] }
}
```

- **P2P**: BitTorrent and eDonkey/Kad (eMule, and the P2P side of Xunlei). A TCP connection opening with the BitTorrent peer handshake, an HTTP tracker announce or scrape, or an eDonkey hello is refused, as is a UDP session opening with uTP, DHT, a UDP tracker request or a Kad message. Later DHT, tracker and Kad packets in an open UDP session are dropped and the session carries on. Encrypted BitTorrent (MSE), obfuscated eDonkey and HTTPS trackers cannot be told apart from other encrypted traffic and pass.
- **Blocked ports**: connections and UDP packets to these ports are refused. The default blocks SMTP (25), the port spam goes out on (mail clients submit on 465 and 587, which stay open), and MS-RPC and NetBIOS/SMB (135, 137-139, 445), which worms spread on and which many ISPs block anyway; file shares across the internet, such as Azure Files over SMB, need 445 taken off the list. An empty list blocks nothing.
- **Port scans**: a user whose TCP connections fail for more than `failed_destinations` different destinations, or who reaches more than `ports_per_host` ports of one host, within `window`, is banned on this node. Refused and timed-out connections count. Failures that say more about the node than about the user do not: networks the node has no route to (IPv6 on a node without it), private addresses the node refuses itself, and anything that fails while nothing on the node gets through, as when its uplink or `front_proxy` is down.
- **Floods**: a user who opens more than `connections` TCP connections, or more than `connections_per_destination` to one destination (host and port), within `window`, is banned on this node. Many requests inside one kept-alive or HTTP/2 connection are encrypted and cannot be counted; the speed limit is what bounds them.
- **Brute force**: on login ports (SSH, Telnet, FTP, RDP, VNC, WinRM and databases), a user who reaches more than `hosts` different hosts, or opens more than `connections_per_destination` TCP connections to one host and port, within `window`, is banned on this node. The first is credential spraying, the second hammering one server. Git over SSH counts its host once, however many repositories it fetches, but a tool that opens a new SSH connection per task to many servers (Ansible without connection reuse, for example) can reach `hosts`; raise it for users who manage fleets through the node.

A ban closes the user's open connections on this node and refuses new ones, TCP and UDP, for `ban_duration`. Other users and other nodes are not affected, and the ban does not survive a restart. Windows are fixed, starting with the user's first connection after the previous window ended, and a threshold of 0 takes the default.

Bans are logged at warn. A refused P2P or blocked-port connection is logged at info once a minute per user and kind, naming the protocol, and at debug otherwise. Setting `rule_id` to the ID of a detect rule in the panel reports hits to the panel as hits of that rule, once a minute per user and kind and once per ban, so they appear in its detect log and count toward its automatic ban (`auto_detect_ban_number`). Create one plaintext rule per kind, for example "P2P (node)", with a regex that matches nothing real, such as `^nextserver-abuse-p2p$`, since the node also applies the rule as a normal detect rule. 0 reports nothing.

### Behaviour worth knowing

- Speed limits come from the panel in Mbps. A user gets the stricter of the node's and their own limit, in each direction.
- When the panel stops serving a user (expired, out of traffic, banned), their open connections are closed at the next pull. When the panel answers `out_of_bandwidth` or `node_disabled`, all users stop until it serves them again.
- Detect rules of the plaintext type match the destination host, the sniffed domain and the first payload as text. Hexadecimal rules match the first payload hex encoded, in lower case. A hit closes the connection and is reported.
- Traffic and detect logs that fail to reach the panel are not lost or counted twice. Each batch carries a random `report_id`; one that got no answer (a timeout, a dropped connection, a 5xx) is sent again unchanged on the next push, and the panel records a batch only once per ID. New traffic waits until it has gone through. A batch the panel refuses (4xx) was not recorded, so its counts go back into the next batch. Shutting down sends a final report, after any batch still waiting. A panel older than `report_id` ignores it, and a resend after a timeout can then still be counted twice there.
- PROXY protocol without `proxy_protocol_trusted` lets any client choose its reported address. Use it only behind a relay, or with a firewall.
- Users cannot reach the node itself or the networks only it can reach: the addresses of its own interfaces (public ones too, read again on every pull), loopback, private, link-local (a cloud's metadata service among them), CGNAT, multicast and broadcast addresses, given directly or resolved from a domain. A node behind 1:1 NAT, as on most clouds, does not see its public address; a connection to that address goes out through the NAT and comes back from outside, like anyone else's. A domain keeps its public addresses. UDP packets to such addresses are dropped. `allow_private_destinations` lifts this, e.g. for a node that serves an intranet. With a `front_proxy` that resolves domains itself, only addresses are checked.

## Build

```bash
make build                                   # default tags: with_acme,with_utls,with_quic
make build EXTRA_TAGS=with_sentry,with_pprof # with the optional features
make test                                    # unit and end-to-end tests
next-server version                          # version and the tags a binary was built with
```

| Tag | Enables | Default |
| --- | --- | --- |
| `with_acme` | `tls.acme` certificates | yes |
| `with_utls` | uTLS-based TLS features of sing-box | yes |
| `with_quic` | the VMess and Trojan `quic` transport, and the TUIC/Hysteria2 end-to-end tests | yes |
| `with_sentry` | the `sentry` option | no |
| `with_pprof` | the `pprof` option | no |

Go cannot make build tags a module default, so a plain `go build` has none of them. The Makefile, CI, release builds and the VS Code workspace settings all use the default tags, and a binary built without them says so in its first log line. Configuring `sentry` or `pprof` in a binary built without their tag is an error.

### Sentry

```jsonc
"sentry": {
  "dsn": "https://key@sentry.example.com/1",   // or the SENTRY_DSN environment variable
  "environment": "production",
  "crash_file": "/var/lib/next-server/crash"   // optional
}
```

Server errors (the panel unreachable, a listener failing), failed starts and panics in the update loops are reported, tagged with the release version. A panic anywhere else, such as in a connection, ends the process before it can be reported; with `crash_file` the runtime writes the crash there and it is sent on the next start. A `with_sentry` build without a `sentry` section still reports when `SENTRY_DSN` is set.

Problems with single connections are never reported, since a public node sees them constantly: a client going away is logged at debug, and a destination refusing, a scanner probing or a malformed request at warn. As a safety net, messages that differ only in numbers (addresses, ports, IDs) count as one problem and are sent at most once every 10 minutes, with a `suppressed` tag counting the rest, and a node sends at most 10 events at once and one per 10 seconds after that.

### Profiling and profile-guided optimization

```jsonc
"pprof": {
  "listen": "127.0.0.1:6060",                       // net/http/pprof, no authentication
  "cpu_profile": "/var/lib/next-server/cpu.pprof"   // recorded from start to shutdown
}
```

Go applies `cmd/next-server/default.pgo` to every build of `cmd/next-server` automatically. To create or refine it, run a `with_pprof` build under real load and, from a machine that can reach its pprof listener:

```bash
make pgo PPROF_URL=http://127.0.0.1:6060 PPROF_SECONDS=60
```

This records a CPU profile and merges it into `default.pgo`; repeat on several nodes for a representative profile. The file is always committed with the code, and CI and release builds fail without it. A `cpu_profile` file can be merged the same way with `go tool pprof -proto cmd/next-server/default.pgo cpu.pprof > merged.pprof`.
