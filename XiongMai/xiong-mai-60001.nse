local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"xiongmai_60001"}

description = [[
雄迈视频设备存在后台管理页面，端口60001，易受到口令爆破攻击。
]]

portrule = shortport.port_or_service( {60001}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local path = "/"
	local path2 = "/view2.html"
	local check_str = "onDblClick"
	local check_text = "Network video client"
	local check_view2 = "view2.js"
	local r = http.get(host, port, path)
	local r1 = http.get(host, port, path2)

	if r.status == 200 and r1.status == 200 then
		if string.find(r.body, check_str) ~= nil and string.find(r.body, check_text) ~= nil and string.find(r1.body, check_view2) ~= nil then
			output = "Found Vulnerable"
		else
			output = "Not Vulnerable"
		end
	else
		output = "Not Vulnerable"
	end
	return output

end
