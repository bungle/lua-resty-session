local setmetatable = setmetatable
local shared = ngx.shared
local assert = assert
local error = error


local DEFAULT_ZONE = "sessions"


local function get_name(self, key)
  local prefix = self.prefix
  local suffix = self.suffix
  if prefix and suffix then
    return prefix .. key .. suffix
  elseif prefix then
    return prefix .. key
  elseif suffix then
    return key .. suffix
  else
    return key
  end
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl)
  local ok, err = self.dict:set(get_name(self, key), value, ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:get(key)
  local value, err = self.dict:get(get_name(self, key))
  if not value then
    return nil, err
  end
  return value
end


function metatable:ttl(key)
  local ttl, err = self.dict:ttl(get_name(self, key))
  if not ttl then
    return nil, err
  end
  return ttl
end


function metatable:expire(key, ttl)
  local ok, err = self.dict:expire(get_name(self, key), ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:delete(key)
  self.dict:delete(get_name(self, key))
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
