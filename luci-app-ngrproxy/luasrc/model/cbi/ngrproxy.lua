local uci = require "luci.model.uci".cursor()
local util = require "luci.util"

local function collect_known_hosts()
    local hosts = {}
    local seen = {}

    -- Static DHCP leases (/etc/config/dhcp)
    uci:foreach("dhcp", "host", function(s)
        local ip = s.ip
        local name = s.name or s.hostname or s.mac or ip
        if ip and ip ~= "" and not seen[ip] then
            seen[ip] = true
            hosts[#hosts + 1] = { ip = ip, label = string.format("%s (static: %s)", ip, name) }
        end
    end)

    -- Dynamic DHCP leases (/tmp/dhcp.leases)
    local lease_file = "/tmp/dhcp.leases"
    local f = io.open(lease_file, "r")
    if f then
        for line in f:lines() do
            local _, mac, ip, hostname = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            if ip and ip ~= "" and not seen[ip] then
                seen[ip] = true
                hostname = (hostname and hostname ~= "*") and hostname or mac or "client"
                hosts[#hosts + 1] = { ip = ip, label = string.format("%s (dynamic: %s)", ip, hostname) }
            end
        end
        f:close()
    end

    table.sort(hosts, function(a, b) return a.ip < b.ip end)
    return hosts
end

local known_hosts = collect_known_hosts()

m = Map("ngrproxy", translate("NGRProxy"), translate("OpenWrt-native reverse proxy manager for hardened HTTP(S) termination and TLS passthrough services."))

s = m:section(TypedSection, "global", translate("Global settings"))
s.anonymous = true

enabled = s:option(Flag, "enabled", translate("Enable service"))
enabled.default = enabled.disabled

auto_reload = s:option(Flag, "reload_nginx", translate("Reload nginx on apply"))
auto_reload.default = auto_reload.enabled
auto_reload.rmempty = false

http_include_dir = s:option(Value, "http_include_dir", translate("HTTP include directory"))
http_include_dir.default = "/etc/nginx/conf.d"

stream_include_dir = s:option(Value, "stream_include_dir", translate("Stream include directory"))
stream_include_dir.default = "/etc/nginx/stream.d"

h = m:section(TypedSection, "http_host", translate("HTTP(S) virtual hosts"), translate("Each entry terminates client HTTP/TLS at nginx and forwards to an upstream. Upstream TLS verification is mandatory when using HTTPS upstreams."))
h.template = "cbi/tblsection"
h.addremove = true
h.anonymous = true

h_enabled = h:option(Flag, "enabled", translate("Enabled"))
h_enabled.default = h_enabled.enabled

h_name = h:option(Value, "name", translate("Name"))
h_name.datatype = "uciname"

h_domain = h:option(Value, "domain", translate("Domain (server_name)"))
h_domain.datatype = "host"
h_domain.rmempty = false

h_listen_http = h:option(Flag, "listen_http", translate("Listen on HTTP/80"))
h_listen_http.default = h_listen_http.disabled

h_listen_https = h:option(Flag, "listen_https", translate("Listen on HTTPS/443"))
h_listen_https.default = h_listen_https.enabled

h_cert = h:option(Value, "tls_cert", translate("TLS certificate (PEM)"))
h_cert.placeholder = "/etc/nginx/certs/example.crt"
h_cert:depends("listen_https", "1")

h_key = h:option(Value, "tls_key", translate("TLS private key (PEM)"))
h_key.placeholder = "/etc/nginx/certs/example.key"
h_key:depends("listen_https", "1")

h_upstream_scheme = h:option(ListValue, "upstream_scheme", translate("Upstream scheme"))
h_upstream_scheme:value("http", "HTTP")
h_upstream_scheme:value("https", "HTTPS (verified)")
h_upstream_scheme.default = "http"

h_upstream_target = h:option(ListValue, "upstream_target", translate("Upstream host from DHCP leases"))
for _, host in ipairs(known_hosts) do
    h_upstream_target:value(host.ip, host.label)
end
h_upstream_target:value("manual", translate("Manual host/IP entry"))
h_upstream_target.default = "manual"

h_upstream_host = h:option(Value, "upstream_host", translate("Manual upstream host/IP"))
h_upstream_host.rmempty = false
h_upstream_host.placeholder = "10.0.0.10"
h_upstream_host:depends("upstream_target", "manual")

h_upstream_port = h:option(Value, "upstream_port", translate("Upstream port"))
h_upstream_port.datatype = "port"
h_upstream_port.default = 8080

h_upstream_sni = h:option(Value, "upstream_sni", translate("Upstream TLS SNI/hostname"))
h_upstream_sni.placeholder = "backend.internal.example"
h_upstream_sni:depends("upstream_scheme", "https")

h_upstream_ca = h:option(Value, "upstream_ca", translate("Upstream CA bundle path"))
h_upstream_ca.placeholder = "/etc/ssl/certs/internal-ca.pem"
h_upstream_ca:depends("upstream_scheme", "https")

h_thumb = h:option(DummyValue, "_thumbnail", translate("Preview"))
h_thumb.rawhtml = true
function h_thumb.cfgvalue(self, section)
    local target = m.uci:get("ngrproxy", section, "upstream_target") or "manual"
    local host = (target ~= "manual") and target or (m.uci:get("ngrproxy", section, "upstream_host") or "")
    local port = m.uci:get("ngrproxy", section, "upstream_port") or "80"
    local scheme = m.uci:get("ngrproxy", section, "upstream_scheme") or "http"

    if host == "" then
        return "-"
    end

    local url = string.format("%s://%s:%s/", scheme, host, port)
    local esc = util.pcdata(url)
    return string.format('<a href="%s" target="_blank">%s</a><br/><img src="%s://%s:%s/favicon.ico" style="max-height:24px;max-width:24px"/>', esc, esc, scheme, util.pcdata(host), util.pcdata(port))
end

st = m:section(TypedSection, "stream_host", translate("TCP/TLS passthrough hosts"), translate("Use for mail and other encrypted services that must remain end-to-end encrypted. nginx forwards TCP without decrypting payload."))
st.template = "cbi/tblsection"
st.addremove = true
st.anonymous = true

st_enabled = st:option(Flag, "enabled", translate("Enabled"))
st_enabled.default = st_enabled.enabled

st_name = st:option(Value, "name", translate("Name"))
st_name.datatype = "uciname"

st_listen_addr = st:option(Value, "listen_addr", translate("Listen address"))
st_listen_addr.placeholder = "0.0.0.0"
st_listen_addr.default = "0.0.0.0"

st_listen_port = st:option(Value, "listen_port", translate("Listen port"))
st_listen_port.datatype = "port"
st_listen_port.rmempty = false

st_upstream_target = st:option(ListValue, "upstream_target", translate("Upstream host from DHCP leases"))
for _, host in ipairs(known_hosts) do
    st_upstream_target:value(host.ip, host.label)
end
st_upstream_target:value("manual", translate("Manual host/IP entry"))
st_upstream_target.default = "manual"

st_upstream_host = st:option(Value, "upstream_host", translate("Manual upstream host/IP"))
st_upstream_host.rmempty = false
st_upstream_host.placeholder = "10.0.0.20"
st_upstream_host:depends("upstream_target", "manual")

st_upstream_port = st:option(Value, "upstream_port", translate("Upstream port"))
st_upstream_port.datatype = "port"
st_upstream_port.rmempty = false

return m
