local setmetatable = setmetatable
local error = error
local byte = string.byte


local SLASH_BYTE = byte("/")


local DEFAULT_POOL = "default"
local DEFAULT_PATH do
  local path = os.tmpname()
  local pos
  for i = #path, 1, -1 do
    if byte(path, i) == SLASH_BYTE then
      pos = i
      break
    end
  end

  DEFAULT_PATH = path:sub(1, pos)
end


local run_worker_thread do
  run_worker_thread = ngx.run_worker_thread
  if not run_worker_thread then
    local require = require
    run_worker_thread = function(_, module, func, ...)
      local m = require(module)
      return m[func](...)
    end
  end
end


local function get_path(self, key)
  local prefix = self.prefix
  local suffix = self.suffix
  if prefix and suffix then
    return self.path .. prefix .. key .. suffix
  elseif prefix then
    return self.path .. prefix .. key
  elseif suffix then
    return self.path .. key .. suffix
  else
    return self.path .. key
  end
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value)
  return run_worker_thread(self.pool, "resty.session.file-thread", "set", get_path(self, key), value)
end


function metatable:get(key)
  return run_worker_thread(self.pool, "resty.session.file-thread", "get", get_path(self, key))
end

-- TODO: deletion of expired files
-- TODO: adjustments to file expiry
--function metatable:ttl(key)
--  local ttl, err = self.dict:ttl(key)
--  if not ttl then
--    return nil, err
--  end
--  return ttl
--end
--
--
--function metatable:expire(key, ttl)
--  local ok, err = self.dict:expire(key, ttl)
--  if not ok then
--    return nil, err
--  end
--  return true
--end


function metatable:delete(key)
  return run_worker_thread(self.pool, "resty.session.file-thread", "delete", get_path(self, key))
end


local storage = {}


function storage.new(configuration)
  local prefix = configuration and configuration.prefix --or DEFAULT_PREFIX
  local suffix = configuration and configuration.suffix --or DEFAULT_SUFFIX

  local pool   = configuration and configuration.pool or DEFAULT_POOL
  local path   = configuration and configuration.path or DEFAULT_PATH

  if byte(path, -1) ~= SLASH_BYTE then
    path = path .. "/"
  end

  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    pool = pool,
    path = path,
  }, metatable)
end


return storage
