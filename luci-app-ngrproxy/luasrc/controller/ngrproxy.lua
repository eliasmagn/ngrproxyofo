module("luci.controller.ngrproxy", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/ngrproxy") then
        return
    end

    entry({"admin", "services", "ngrproxy"}, cbi("ngrproxy"), _("NGRProxy"), 65).dependent = true
    entry({"admin", "services", "ngrproxy", "apply"}, call("action_apply")).leaf = true
    entry({"admin", "services", "ngrproxy", "thumbnail"}, call("action_thumbnail")).leaf = true
end

function action_apply()
    local http = require "luci.http"
    local sys = require "luci.sys"

    local ok = (sys.call("/etc/init.d/ngrproxy reload >/tmp/ngrproxy.apply.log 2>&1") == 0)
    http.prepare_content("application/json")
    http.write_json({ ok = ok, log = "/tmp/ngrproxy.apply.log" })
end

function action_thumbnail()
    local http = require "luci.http"
    local protocol = require "luci.http.protocol"
    local uci = require "luci.model.uci".cursor()

    local url = http.formvalue("url") or ""
    if url == "" then
        http.status(400, "Missing url")
        http.write("missing url")
        return
    end

    local endpoint = uci:get("ngrproxy", "settings", "thumbnail_endpoint") or ""
    if endpoint == "" then
        http.status(404, "Thumbnail endpoint not configured")
        http.write("thumbnail endpoint is not configured")
        return
    end

    local redirect = endpoint:gsub("%%s", protocol.urlencode(url))
    http.redirect(redirect)
end
