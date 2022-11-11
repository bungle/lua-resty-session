local setmetatable = setmetatable
local shared = ngx.shared
local error = error


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl)
  local ok, err = self.dict:set(key, value, ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:get(key)
  local value, err = self.dict:get(key)
  if not value then
    return nil, err
  end
  return value
end


function metatable:ttl(key)
  local ttl, err = self.dict:ttl(key)
  if not ttl then
    return nil, err
  end
  return ttl
end


function metatable:expire(key, ttl)
  local ok, err = self.dict:expire(key, ttl)
  if not ok then
    return nil, err
  end
  return true
end


function metatable:delete(key)
  self.dict:delete(key)
  return true
end


local storage = {}


function storage.new(configuration)
  local zone
  if configuration then
    zone = configuration.zone
  end

  zone = zone or "sessions"

  return setmetatable({
    dict = shared[zone],
  }, metatable)
end


return storage
