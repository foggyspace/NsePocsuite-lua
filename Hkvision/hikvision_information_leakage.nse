local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"


author = "seaung"

description = [[
Hikvision DV 泄露web版本信息
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "hikvision", "hikvision_information_leakage", "vuln_detect" }

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local path = "/doc/script/lib/seajs/config/sea-config.js?version="

    local response = http.get(host, port, path)

	if response.status == 200 then
		if string.find(response.body, "seajs.web_version") ~= nil and string.find(response.body, "seajs.plugin_version") ~= nil then
			output.yd_web_version = string.match(response.body, "(%u%w.%w.%d%a+%d+)")
			output.yd_plugin_version = string.match(response.body, "(%u%w.%d+.%d+.%d+)")
			output.yd_info = "Found vulnerable"
		else
			output.yd_info = "Not vulnerable"
		end
	else
		output.yd_info = "Bad Request"
	end
	return output
end

