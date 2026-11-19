# Changelog

## v1.3.0

### Added

- **Exploit and mining checks.** Built-in signatures refuse exploit attempts in plain HTTP (Log4Shell, SQL injection, path traversal to system files, malware droppers, PHP-CGI argument injection, Spring4Shell, Apache's cgi-bin traversal) and logins to mining pools over plain Stratum (Stratum v1, XMRig-style logins, EthProxy). Both are on by default; `abuse.exploits` and `abuse.mining` turn them off or report hits to the panel under a detect rule.
- **Live signature updates.** `abuse.signatures.path` (a file on the node) and `abuse.signatures.url` (HTTPS) add, replace or turn off signatures by name. They are read again on every pull, without a restart; a broken update is reported once and the last good signatures stay in force.

## v1.2.1

### Changed

- The connection flood check bans a user for more than 500 connections to one destination within 10 seconds, up from 200. On v1.2.0's first day in production the only flood ban was an app retrying an API (201 connections to `open.feishu.cn:443`), not a flood; real HTTP floods run far above 500. Nodes that set `abuse.flood.connections_per_destination` keep their value.

## v1.2.0

### Security

- Users can no longer reach the node through its own public addresses. v1.0.1 refused loopback and private networks, but a service listening on all interfaces (a monitoring agent, a database, SSH) was still reachable at the node's public IPv4 or IPv6 address, with the node itself as the source, which firewall rules that allow the node's own address let through. Every address on the node's interfaces is now refused, read again on every pull so that a PPPoE or DHCP node's new address is covered. `allow_private_destinations` lifts this as before.

### Fixed

- Hexadecimal detect rules were matched as plaintext rules. NeXT-Panel stores them as type 0, but v1 took type 2 for hexadecimal and anything else for plaintext, so a hex regex such as `^1603` was matched against the raw payload and practically never hit. Rule types other than 0 and 1 are now reported and skipped.

### Added

- **Abuse checks** that run on every node without detect rules: P2P file sharing (BitTorrent peer handshake, HTTP and UDP trackers, uTP and DHT; eDonkey and Kad) is refused, SMTP (25) and MS-RPC/NetBIOS/SMB (135, 137-139, 445) are blocked, and a user who port-scans, floods connections or brute-forces login ports (SSH, RDP, databases and the like) is banned on that node for 10 minutes, with their open connections closed. All on by default; the new `abuse` section changes thresholds and ports, turns checks off, or reports hits to the panel under a detect rule so they count toward its automatic ban. See "Abuse checks" in the README.

## v1.1.0

### Fixed

- **Traffic and detect logs are no longer counted twice when the panel's answer is lost.** A report that failed for any reason used to be merged back into the counters and sent again inside the next batch. When the panel had recorded the first attempt and only its answer was lost (a request timeout, a gateway 504 while the panel kept working, a connection reset after it committed), the same traffic was billed twice, and detect rule hits counted twice toward the automatic ban.

  Each traffic and detect log batch now carries a random `report_id`, and the panel records a batch once per ID. A batch that got no answer or a 5xx is sent again unchanged on the next push, before anything new is collected; new traffic keeps counting meanwhile and goes in the next batch. A batch the panel refuses (4xx) was not recorded, so its counts go back into the next batch, as before. Shutting down sends any batch still waiting, then the final traffic and, new, the final detect logs.

  A panel without `report_id` support ignores the field and behaves as before, where a resend after a lost answer can still be counted twice.

### Dependencies

- Go 1.27.4, and the indirect dependencies that follow sing-box 1.14.4.

## v1.0.4

### Dependencies

- sing-box 1.14.4 and golang.org/x/net 0.62.0. No functional changes.

## v1.0.3

### Dependencies

- sing-box 1.14.3 and Go 1.27.3. No functional changes.

## v1.0.2

### Performance

- The profile-guided optimization profile (`default.pgo`) now includes v1.0.1 profiles from four production nodes under real load, alongside the previous ones. No functional changes.

## v1.0.1

### Security

- Users can no longer reach the node itself or its private networks through it: loopback, private, link-local (including a cloud's metadata service, such as 169.254.169.254), CGNAT, multicast and broadcast addresses, whether given directly or resolved from a domain. A domain keeps its public addresses, and later UDP packets to such addresses are dropped. v1.0.0 and v0 let them through. Set `allow_private_destinations` for a node that should serve an intranet.

### Fixed

- With `acme`, a client asking for a name the certificates do not cover, such as a CDN sending its own name, gets the node's certificate (`default_server_name`, or the first `domain`) instead of a failed handshake. A node behind a CDN can now renew its certificate: set `tls.acme.domain` to the node's own name instead of copying a fixed certificate.

## v1.0.0

NeXT-Server is rewritten on [sing-box](https://github.com/SagerNet/sing-box) 1.14, replacing Xray-core. The v0 line lives on the `v0` branch.

### Breaking changes

- **Panel API.** v1 talks to NeXT-Panel's Server API V1 (`/api/server/v1`) with each node's own communication key. The shared `muKey` and `/mod_mu` are no longer used. If the panel sits behind Cloudflare or another firewall that only lets `/mod_mu` through, allow `/api/server/v1/*` as well.
- **Configuration.** The YAML file is replaced by JSON (`/etc/next-server/config.json`, comments allowed); see the README. The node type, port and transport now come from the panel, so `NodeType`, `NodeID` and the custom inbound, outbound, route and DNS files are gone.
- **Certificates.** `CertConfig` is replaced by the sing-box `tls` block: `certificate_path`/`key_path`, or `acme` (DNS-01 through Cloudflare, AliDNS or ACME-DNS).
- **Node types.** Supported: Shadowsocks 2022, TUIC v5, Hysteria2, AnyTLS, VMess and Trojan. Snell and NaïveProxy are not supported yet, and the plain Shadowsocks multi-port mode is gone with the panel's removal of it.

### Migrating a node from v0

```jsonc
{
  "log": { "level": "warn" },
  "servers": [
    {
      "url": "https://<ApiHost>",
      "key": "<the node's communication key, not the muKey>",
      "listen": "::",
      // Either reuse the certificate v0 obtained...
      "tls": {
        "certificate_path": "/etc/next-server/cert/certificates/<CertDomain>.crt",
        "key_path": "/etc/next-server/cert/certificates/<CertDomain>.key"
      }
      // ...or let v1 renew it: "tls": { "acme": { "email": "<Email>", "dns01_challenge": { "provider": "cloudflare", "api_token": "<CF_DNS_API_TOKEN>" } } }
    }
  ]
}
```

A v0 certificate is not renewed once v0 stops; switch to `acme` before it expires.

### New

- Users are updated in place: a user list change never restarts the listener or drops other users' connections, and a removed user's open connections are closed.
- Traffic is kept across user updates and failed reports, and reported once more on shutdown.
- Speed limits apply the stricter of the node's and the user's limit, per direction.
- Detect rules are enforced on the destination, the sniffed domain and the first payload, and hits are reported.
- Opt-in PROXY protocol, with a list of trusted relays.
- sing-mux, UDP over TCP, and all sing-box V2Ray transports (WebSocket, HTTP, HTTPUpgrade, gRPC, QUIC).
- Optional Sentry reporting (`-tags with_sentry`), with per-connection noise kept out and a rate limit, and crash reports from any goroutine.
- Optional pprof (`-tags with_pprof`). Builds use the committed `default.pgo` for profile-guided optimization, collected on production nodes.
- `next-server version` prints the version and the build tags.

### Tested

End-to-end tests drive every supported protocol through real sing-box clients against a fake panel built from NeXT-Panel's Server API V1 controller, and run under the race detector on Linux. A trial build served a production Trojan + gRPC node with 461 users before the release.
