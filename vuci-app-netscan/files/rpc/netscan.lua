local os = require "os"
local utils = require "vuci.utils"
local cjson = require "vuci.json"

local M = {}

HOSTS = "/tmp/hosts.json"

function M.start_scan(params)
    local cmd = "lua /usr/lib/vuci-httpd/rpc/nethosts"
    if params.subnet ~= nil then
        cmd = cmd .. " -a "..params.subnet
    end
    cmd = cmd .. " &> /tmp/hosts.json &"
    os.execute(cmd)
    return {ok = false,data = nil}
end

function M.get_results()
  local data
  local file = utils.readfile(HOSTS)
  if file then
    data = cjson.decode(file)
    if data == nil then
      local lines = {}
      for line in io.lines("/tmp/hosts.json") do
        lines[#lines + 1] = line
      end
      if next(lines) == nil then
        return { ok = false, data =  nil}
      end
      return { ok = true, data =  lines, type = "error"}
    end
    return { ok = true, data = data, type = "hosts"}
  end
end

function M.stop_scan()
    os.execute("pgrep -f \"lua /usr/lib/vuci-httpd/rpc/nethosts\" | xargs kill -9")
    os.execute("pidof nmap | xargs kill -9")
    return {ok = true, data = nil}
end

return M