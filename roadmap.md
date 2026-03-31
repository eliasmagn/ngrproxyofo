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
- Better error UX in LuCI.
- OpenWrt version compatibility and package tests.
- Migration helper for earlier ngrproxy configurations.

## Phase 4 — Advanced features (Planned)
- Optional richer thumbnail/screenshot integrations.
- Policy controls (ACL, PROXY protocol, rate limits).
- Backup/export and restoration workflows.
