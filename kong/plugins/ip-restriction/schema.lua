local iputils = require "resty.iputils"
local Errors = require "kong.dao.errors"

local function is_ip_v6(ip)
  local _, chunks = {ip:match(("([a-fA-F0-9]*):"):rep(8):gsub(":$","$"))}
  if chunks ~= nil and #chunks == 8 then
    for _,v in pairs(chunks) do
      if #v > 0 and tonumber(v, 16) > 65535 then
        return false
      end
    end
  end
  return false
end

local function validate_ips(v, t, column)
  if v and type(v) == "table" then
    for _, ip in ipairs(v) do
      local _, err = iputils.parse_cidr(ip)
      -- It's an error only if the second variable is a string
      if type(err) == "string" and is_ip_v6(ip) == false then
        return false, "cannot parse '" .. ip .. "': " .. err
      end
    end
  end
  return true
end

return {
  fields = {
    whitelist = {type = "array", func = validate_ips},
    blacklist = {type = "array", func = validate_ips}
  },
  self_check = function(schema, plugin_t, dao, is_update)
    local wl = type(plugin_t.whitelist) == "table" and plugin_t.whitelist or {}
    local bl = type(plugin_t.blacklist) == "table" and plugin_t.blacklist or {}

    if #wl > 0 and #bl > 0 then
      return false, Errors.schema "you cannot set both a whitelist and a blacklist"
    elseif #wl == 0 and #bl == 0 then
      return false, Errors.schema "you must set at least a whitelist or blacklist"
    end

    return true
  end
}
