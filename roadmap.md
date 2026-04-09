# Roadmap

## Phase 1 — Secure core (Done)
- UCI-first model with LuCI integration.
- Split `http_host` and `stream_host` service classes.
- Enforced HTTPS upstream trust requirements.

## Phase 2 — LAN usability (Done)
- Upstream selection from static and dynamic DHCP lease sources.
- Manual override support for non-DHCP or external upstreams.
- Basic LuCI upstream preview support.

## Phase 3 — Operational maturity (In progress)
- Better error UX in LuCI. ✅
- Migration helper for earlier ngrproxy configurations. ✅
- OpenWrt version compatibility and package tests (scripted runner added; multi-SDK execution pending).

## Phase 4 — Advanced features (In progress)
- Optional thumbnail/screenshot endpoint integration. ✅
- Policy controls: per-host ACL + optional PROXY protocol (implemented for stream and ACL for HTTP/stream). ✅
- Backup/export and restoration workflows. (planned)
