# NGRProxy

NGRProxy is an OpenWrt/LuCI app that manages nginx reverse-proxy configuration via UCI with hardened defaults and DHCP-aware upstream selection.

## Highlights
- UCI-first OpenWrt model (`/etc/config/ngrproxy`).
- Per-host classes:
  - `http_host` for HTTP/TLS reverse proxies.
  - `stream_host` for encrypted TCP passthrough (mail and similar protocols).
- Secure HTTPS upstream handling:
  - requires SNI (`upstream_sni`),
  - requires trusted CA bundle (`upstream_ca`),
  - enforces verification for HTTPS backends.
- Upstream host dropdown populated from:
  - static DHCP leases (`/etc/config/dhcp`),
  - dynamic leases (`/tmp/dhcp.leases`).
- LuCI preview helper with upstream URL + favicon thumbnail.
- Optional screenshot thumbnail endpoint integration via LuCI controller redirect.
- Per-host ACL controls for HTTP and stream hosts.
- Optional PROXY protocol support for stream listeners/upstreams.
- Legacy config migration utility (`/usr/libexec/ngrproxy/migrate.sh`).

## Package layout
- `luci-app-ngrproxy/Makefile`
- `luci-app-ngrproxy/luasrc/controller/ngrproxy.lua`
- `luci-app-ngrproxy/luasrc/model/cbi/ngrproxy.lua`
- `luci-app-ngrproxy/root/etc/config/ngrproxy`
- `luci-app-ngrproxy/root/etc/init.d/ngrproxy`
- `luci-app-ngrproxy/root/usr/libexec/ngrproxy/render.sh`
- `luci-app-ngrproxy/root/usr/share/rpcd/acl.d/luci-app-ngrproxy.json`

## Deploy (OpenWrt buildroot)
1. Add/copy `luci-app-ngrproxy` into your OpenWrt feed tree.
2. Run:
   - `./scripts/feeds update -a`
   - `./scripts/feeds install luci-app-ngrproxy`
3. Enable package in `make menuconfig`.
4. Build and install package.

## Runtime notes
1. Ensure nginx includes:
   - `include /etc/nginx/conf.d/*.conf;` in `http {}`
   - `include /etc/nginx/stream.d/*.conf;` in `stream {}`
2. Configure hosts in LuCI and apply.
3. Generated symlinks:
   - `/etc/nginx/conf.d/zz-ngrproxy-generated.conf`
   - `/etc/nginx/stream.d/zz-ngrproxy-generated.conf`
4. Optional global screenshot endpoint:
   - Set `settings.thumbnail_endpoint` with `%s` placeholder (URL-encoded upstream URL is substituted).
5. Migration:
   - Service startup runs legacy migration once, guarded by `/etc/ngrproxy/.migrated-v1`.
