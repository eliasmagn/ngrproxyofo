module("luci.controller.ngrproxy", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/ngrproxy") then
        return
    end

    entry({"admin", "services", "ngrproxy"}, cbi("ngrproxy"), _("NGRProxy"), 65).dependent = true
    entry({"admin", "services", "ngrproxy", "apply"}, call("action_apply")).leaf = true
end

function action_apply()
    local http = require "luci.http"
    local sys = require "luci.sys"

    local ok = (sys.call("/etc/init.d/ngrproxy reload >/tmp/ngrproxy.apply.log 2>&1") == 0)
    http.prepare_content("application/json")
    http.write_json({ ok = ok, log = "/tmp/ngrproxy.apply.log" })
end
