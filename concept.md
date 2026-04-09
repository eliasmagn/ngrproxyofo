# NGRProxy Concept

## Vision
NGRProxy is an OpenWrt-native nginx management app with secure defaults and practical LAN-aware host selection.

## Core principles
1. **UCI-first design**
   - All runtime state is represented in `/etc/config/ngrproxy`.
2. **Per-host policy model**
   - `http_host` for HTTP/TLS termination.
   - `stream_host` for TCP/TLS passthrough (mail/encrypted services).
3. **LAN-aware host discovery**
   - Upstream target can be selected from static DHCP leases (`/etc/config/dhcp`) and dynamic leases (`/tmp/dhcp.leases`).
   - Manual host/IP entry remains available.
4. **No insecure TLS bridging**
   - HTTPS upstream requires SNI hostname and trusted CA bundle.
   - Upstream certificate verification is always on for HTTPS backends.
5. **End-to-end encryption support**
   - Stream passthrough forwards encrypted TCP traffic without backend decryption at proxy.
6. **Fail-closed rendering**
   - Invalid sections abort rendering and nginx reload.
7. **Operator-friendly lifecycle**
   - LuCI validation surfaces precise missing-file feedback before apply.
   - Legacy section migration utility preserves older configs.

## UX additions
- LuCI dropdowns for discovered upstream hosts.
- Lightweight upstream preview in LuCI (`favicon.ico` link + click-through URL).
- Optional screenshot thumbnail endpoint redirect for richer previews.
- Per-host ACL controls and optional PROXY protocol support for stream listeners/upstreams.
