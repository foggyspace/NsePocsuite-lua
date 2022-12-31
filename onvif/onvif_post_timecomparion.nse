local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
local datetime = require "datetime"


description = [[
视频设备时间戳与系统时间偏差5分钟以上，会导致视频录像时间较大偏差。
]]


author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln_detect", "onvif_post_timecomparion"}


portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")


action = function(host, port)
  local sys_time = os.time()
  
  local output_tab = stdnse.output_table()
  local path = "/onvif/device_service"
  local exploit = [[<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>]]
  local options = {header={["Content-Type"]='application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"'}}
  local response = http.post(host, port, path, options, nil, exploit)
  
  local rawheader = response.rawheader
  local body = response.body
  local match_year = "<tt:Year>([^<]*)</tt:Year>"
  local match_month = "<tt:Month>([^<]*)</tt:Month>"
  local match_day = "<tt:Day>([^<]*)</tt:Day>"
  local match_hour = "<tt:LocalDateTime><tt:Time><tt:Hour>([^<]*)</tt:Hour>"
  local match_minute = "<tt:Minute>([^<]*)</tt:Minute>"
  local match_second = "<tt:Second>([^<]*)</tt:Second>"
  
  local ipc_date_year
  local ipc_date_month
  local ipc_date_day
  local ipc_date_hour
  local ipc_date_minute
  local ipc_date_second
  
  if body then
    ipc_date_year = string.match(body, match_year)
    ipc_date_month = string.match(body, match_month)
    ipc_date_day = string.match(body, match_day)
    ipc_date_hour = string.match(body, match_hour)
    ipc_date_minute = string.match(body, match_minute)
    ipc_date_second = string.match(body, match_second)
  end
  
  if not (  ipc_date_year or ipc_date_month or ipc_date_day or ipc_date_hour or ipc_date_minute or ipc_date_second ) then
	output_tab.yd_ipc_date_s = 'get date err'
  else
	local ipc_date = os.time({year=ipc_date_year,month=ipc_date_month,day=ipc_date_day,hour=ipc_date_hour,min=ipc_date_minute,sec=ipc_date_second})
	local diff_time = os.difftime(ipc_date, sys_time)
	diff_time = math.abs(diff_time)
	
	if diff_time >= 60*5 then 
		diff_time_s = 'diff_time greater than 5 minute'
	else
		diff_time_s = 'diff_time less than 5 minute'
	end 
	
	if response.status == 200 or response.status == 401 then
		output_tab.yd_sys_time_s = sys_time
		output_tab.yd_ipc_date_s = ipc_date
		output_tab.yd_diff_time = diff_time
		output_tab.yd_diff_time_s = diff_time_s
	end
  end
  
  return output_tab
  
end
