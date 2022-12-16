---
-- File storage backend for session library
-- @module resty.session.file


local setmetatable = setmetatable
local error = error
local byte = string.byte
local fmt = string.format


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


local function get_path(self, name, key)
  local path = self.path
  local prefix = self.prefix
  local suffix = self.suffix
  if prefix and suffix then
    return fmt("%s%s_%s_%s.%s", path, prefix, name, key, suffix)
  elseif prefix then
    return fmt("%s%s_%s_%s", path, prefix, name, key)
  elseif suffix then
    return fmt("%s%s_%s.%s", path, name, key, suffix)
  else
    return fmt("%s%s_%s", path, name, key)
  end
end


--- File Storage Instance
-- @section file


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


---
-- Store session data.
--
-- @function file:set
-- @tparam  string   name  ...
-- @tparam  string   key   ...
-- @tparam  string   value ...
-- @treturn true|nil       ok
-- @treturn string         error message
function metatable:set(name, key, value)
  return run_worker_thread(self.pool, "resty.session.file-thread", "set", get_path(self, name, key), value)
end

---
-- Retrieve session data.
--
-- @function file:get
-- @tparam  string     name ...
-- @tparam  string     key  ...
-- @treturn string|nil      session data
-- @treturn string          error message
function metatable:get(name, key)
  return run_worker_thread(self.pool, "resty.session.file-thread", "get", get_path(self, name, key))
end


---
-- Delete session data.
--
-- @function file:delete
-- @tparam  string      name ...
-- @tparam  string      key  ...
-- @treturn boolean|nil      session data
-- @treturn string           error message
function metatable:delete(name, key)
  return run_worker_thread(self.pool, "resty.session.file-thread", "delete", get_path(self, name, key))
end


--- File Storage Module
-- @section file

local storage = {}


---
-- File storage backend configuration
-- @field prefix File prefix for session file
-- @field suffix File suffix (or extension without `.`) for session file
-- @field pool Name of the thread pool under which file writing happens (available on Linux only)
-- @field path Path (or directory) under which session files are created
-- @table configuration


---
-- Create a file storage.
--
-- This creates a new file storage instance.
--
-- @function file.new
-- @tparam[opt]  table   configuration  session @{configuration} overrides
-- @treturn      table                  file storage instance
function storage.new(configuration)
  local prefix = configuration and configuration.prefix
  local suffix = configuration and configuration.suffix

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
