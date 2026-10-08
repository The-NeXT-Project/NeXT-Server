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
      "front_proxy": null            // { "type": "socks5"|"socks4"|"socks4a"|"http", "server": "host:port", ... }
    }
  ]
}
```

`servers` may list several nodes; each runs independently.

### TLS certificates

TLS node types (TUIC, Hysteria2, AnyTLS, Trojan, and VMess with `"security": "tls"`) take their certificate from `tls`, which accepts the sing-box inbound TLS fields:

- `certificate_path` and `key_path`: a certificate on disk, reloaded when the files change.
- `acme`: certificates from Let's Encrypt. Leave `domain` empty to use the node's `host` from the panel (or its address, if that is a domain).
- Nothing: a self-signed certificate is generated, and clients connect only with `allow_insecure` set on the node.

The panel's `host` becomes the server name.

### Behaviour worth knowing

- Speed limits come from the panel in Mbps. A user gets the stricter of the node's and their own limit, in each direction.
- When the panel stops serving a user (expired, out of traffic, banned), their open connections are closed at the next pull. When the panel answers `out_of_bandwidth` or `node_disabled`, all users stop until it serves them again.
- Detect rules of type 1 match the destination host, the sniffed domain and the first payload as text. Type 2 rules match the first payload hex encoded. A hit closes the connection and is reported.
- Traffic that fails to reach the panel is kept and sent with the next report. Shutting down sends a final report.
- PROXY protocol without `proxy_protocol_trusted` lets any client choose its reported address. Use it only behind a relay, or with a firewall.

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
