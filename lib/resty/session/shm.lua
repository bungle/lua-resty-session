---
-- Shared Memory (SHM) backend for session library
-- @module resty.session.shm


local get_name = require "resty.session.utils".get_name


local setmetatable = setmetatable
local shared = ngx.shared
local assert = assert
local error = error


local DEFAULT_ZONE = "sessions"


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(name, key, value, ttl)
  local ok, err = self.dict:set(get_name(self, name, key), value, ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:get(name, key)
  local value, err = self.dict:get(get_name(self, name, key))
  if not value then
    return nil, err
  end
  return value
end


function metatable:ttl(name, key)
  local ttl, err = self.dict:ttl(get_name(self, name, key))
  if not ttl then
    return nil, err
  end
  return ttl
end


function metatable:expire(name, key, ttl)
  local ok, err = self.dict:expire(get_name(self, name, key), ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:delete(name, key)
  self.dict:delete(get_name(self, name, key))
  return true
end


local storage = {}


function storage.new(configuration)
  local prefix = configuration and configuration.prefix
  local suffix = configuration and configuration.suffix

  local zone   = configuration and configuration.zone or DEFAULT_ZONE

  local dict = assert(shared[zone], "lua_shared_dict " .. zone .. " is missing")
  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    dict = dict,
  }, metatable)
end


return storage
