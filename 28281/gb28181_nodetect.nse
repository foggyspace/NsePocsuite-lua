local shortport = require "shortport";
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
local nmap = require "nmap"


description = [[
检测目标视频设备是否配置了GB28181
]]

author = "seaung"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"GB28181", "GB28181_nodetect", "vuln_detect"}

portrule = shortport.port_or_service( {554, 5060, 5061}, {"rtsp","sip"}, {"tcp", "udp"} )

action = function(host, port)
  local tmp1
  local tmp2
  local tmp3

  local output = stdnse.output_table()
  
  local p_554 = nmap.get_port_state(host, {number=554, protocol="tcp"})
  local p_5060 = nmap.get_port_state(host, {number=5060, protocol="udp"})
  local p_5061 = nmap.get_port_state(host, {number=5061, protocol="udp"})
  

  if p_554 and (p_554.state == "open" or p_554.state == "open|filtered") then
    tmp1 = 1
  end
  
  if p_5060 and (p_5060.state == "open" or p_5060.state == "open|filtered") then
    tmp2 = 1
  end
  
  if p_5061 and (p_5061.state == "open" or p_5061.state == "open|filtered") then
    tmp3 = 1
  end

  if tmp1 ==1 and not tmp2 and not tmp3 then 
     output = "Found vulnerable.".."Target video device is not configured GB28181"
  else
     output = "Not vulnerable"
  end
  return output
end
