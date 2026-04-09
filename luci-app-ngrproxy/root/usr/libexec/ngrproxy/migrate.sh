#!/bin/sh

set -eu

STAMP="/etc/ngrproxy/.migrated-v1"

mkdir -p /etc/ngrproxy

[ -f "$STAMP" ] && exit 0

# Legacy config support:
# - old section types "host" and "proxy" become "http_host"
for legacy in host proxy; do
	idx=0
	while uci -q get "ngrproxy.@${legacy}[${idx}]" >/dev/null; do
		sec="$(uci -q add ngrproxy http_host)"
		[ -n "$sec" ] || exit 1

		domain="$(uci -q get "ngrproxy.@${legacy}[${idx}].domain" || true)"
		upstream_host="$(uci -q get "ngrproxy.@${legacy}[${idx}].upstream_host" || true)"
		[ -n "$upstream_host" ] || upstream_host="$(uci -q get "ngrproxy.@${legacy}[${idx}].proxyip" || true)"
		upstream_port="$(uci -q get "ngrproxy.@${legacy}[${idx}].upstream_port" || true)"
		[ -n "$upstream_port" ] || upstream_port="$(uci -q get "ngrproxy.@${legacy}[${idx}].proxyport" || true)"
		tls_cert="$(uci -q get "ngrproxy.@${legacy}[${idx}].tls_cert" || true)"
		tls_key="$(uci -q get "ngrproxy.@${legacy}[${idx}].tls_key" || true)"
		listen_https="$(uci -q get "ngrproxy.@${legacy}[${idx}].listen_https" || true)"

		uci -q set "ngrproxy.${sec}.enabled=1"
		[ -n "$domain" ] && uci -q set "ngrproxy.${sec}.domain=${domain}"
		[ -n "$upstream_host" ] && uci -q set "ngrproxy.${sec}.upstream_host=${upstream_host}"
		[ -n "$upstream_port" ] && uci -q set "ngrproxy.${sec}.upstream_port=${upstream_port}"
		[ -n "$tls_cert" ] && uci -q set "ngrproxy.${sec}.tls_cert=${tls_cert}"
		[ -n "$tls_key" ] && uci -q set "ngrproxy.${sec}.tls_key=${tls_key}"
		[ -n "$listen_https" ] && uci -q set "ngrproxy.${sec}.listen_https=${listen_https}"

		uci -q delete "ngrproxy.@${legacy}[${idx}]"
	done
done

uci -q commit ngrproxy
touch "$STAMP"
