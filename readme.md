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

## Output files
- `/tmp/ngrproxy/generated.http.conf`
- `/tmp/ngrproxy/generated.stream.conf`
