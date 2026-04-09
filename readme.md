# NGRProxy status and usage

NGRProxy is now OpenWrt-native and includes DHCP-aware upstream selection.

## What is configurable
- `http_host`: domain-based reverse proxy with optional TLS termination.
- `stream_host`: encrypted TCP passthrough for services like SMTPS/IMAPS.

## Host selection in LuCI
For `http_host` and `stream_host`, upstream can be selected from a dropdown built from:
- static DHCP host reservations (`/etc/config/dhcp`), and
- dynamic DHCP leases (`/tmp/dhcp.leases`).

You can also select **Manual host/IP entry** and type upstream host directly.

## Security
- HTTPS upstream requires `upstream_sni` and `upstream_ca`.
- Renderer fails closed on invalid/incomplete config.
- `nginx -t` is executed before apply/reload succeeds.
- Optional per-host allow/deny ACL is supported for both HTTP and stream hosts.

## New operational tooling
- **LuCI validation feedback** now checks certificate/private key/CA files and reports missing paths directly in form errors.
- **Legacy migration utility** runs on service start: `/usr/libexec/ngrproxy/migrate.sh`
  - Converts legacy `host` / `proxy` sections into `http_host`.
  - Uses stamp file `/etc/ngrproxy/.migrated-v1` to avoid repeated rewrites.
- **SDK package test runner** script: `scripts/run-sdk-package-tests.sh`
  - Run against one or more OpenWrt SDK directories to compile-test `luci-app-ngrproxy`.

## Advanced optional features
- Global setting `thumbnail_endpoint` can be set (with `%s` placeholder) to route preview thumbnails via `/admin/services/ngrproxy/thumbnail`.
- Stream hosts support optional PROXY protocol:
  - `listen_proxy_protocol` (expect PROXY from downstream client/LB),
  - `send_proxy_protocol` (forward PROXY metadata to upstream).

## Output files
- `/tmp/ngrproxy/generated.http.conf`
- `/tmp/ngrproxy/generated.stream.conf`
