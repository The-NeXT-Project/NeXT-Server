# Changelog

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
