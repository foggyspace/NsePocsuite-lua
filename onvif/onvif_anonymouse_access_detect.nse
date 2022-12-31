local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
检测视频设备是否存在onvif类接口的匿名访问漏洞..
]]

author = "seaung"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln_detect", "onvif_anonymouse_access_detect"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)

  local output_tab = stdnse.output_table()
  
  local path = "/onvif/device_service"
  local exploit = [[<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetScopes xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>]]
  local options = {header={["Content-Type"]='application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetScopes"'}}
  local response = http.post(host, port, path, options, nil, exploit)
  local body = response.body
  
  if response.body and response.status == 200 and ( string.match( body, "</s:Envelope>" ) or string.match( body, "</env:Envelope>" ) ) then
     output_tab.display = "Found vulnerable."
  else
     output_tab.display = "Not vulnerable."
  end
  
  return output_tab
end
