# Checklist

## Completed
- [x] Add OpenWrt-native `http_host` / `stream_host` model.
- [x] Enforce trusted HTTPS upstream policy (SNI + CA + verify on).
- [x] Add stream passthrough flow for encrypted services.
- [x] Add dropdown upstream host selection from:
  - [x] static DHCP leases (`/etc/config/dhcp`)
  - [x] dynamic DHCP leases (`/tmp/dhcp.leases`)
- [x] Keep manual host/IP override path.
- [x] Add LuCI preview helper (upstream link + favicon thumbnail).
- [x] Update docs/tracking files to match current architecture.

## Next
- [x] Improve validation feedback text in LuCI for missing cert/CA files.
- [x] Add migration utility for old configs.
- [x] Add OpenWrt SDK package test runner for target releases.
- [x] Add optional screenshot thumbnail endpoint integration.
- [x] Add per-host ACL and optional PROXY protocol support.
- [ ] Execute SDK tests on real target SDK directories (23.05 / 24.10 / snapshot).
