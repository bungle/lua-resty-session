---
-- File storage backend for session library.
--
-- @module resty.session.file


local collections = require "resty.session.scored-collections"


local setmetatable = setmetatable
local error = error
local byte = string.byte
local fmt = string.format
local time = ngx.time


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


---
-- Storage
-- @section instance


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


---
-- Store session data.
--
-- @function instance:set
-- @tparam  string   name  cookie name
-- @tparam  string   key   session key
-- @tparam  string   value session value
-- @tparam  number   ttl   session ttl
-- @tparam  number   current_time  current time
-- @tparam  string   old_key  old session id
-- @tparam  string   stale_ttl  stale ttl
-- @tparam  table    metadata  table of metadata
-- @tparam  table    remember  whether storing persistent session or not
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:set(name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  local inferred_path = get_path(self, name, key)
  if not metadata and not old_key then
    return run_worker_thread(
      self.pool,
      "resty.session.file-thread",
      "set",
      inferred_path,
      value
    )
  end

  local old_path, old_ttl
  if old_key then
    old_path = get_path(self, name, old_key)
    if not remember then
      old_ttl = nil -- TODO (expire implementation): set old_ttl to old_path's ttl
    end
  end

  local ok, res, err = run_worker_thread(
    self.pool,
    "resty.session.file-thread",
    "set",
    inferred_path,
    value
  )
  if not res then
    return nil, err or "set failed"
  end

  if old_path then
    if remember then
      run_worker_thread(
        self.pool,
        "resty.session.file-thread",
        "delete",
        inferred_path
      )
    elseif (not old_ttl or old_ttl > stale_ttl) then
      -- TODO (expire implementation): expire old_path with stale_ttl
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = audiences[i] .. ":" .. subjects[i]
      local exp_score   = (current_time or time()) - 1
      local new_score   = (current_time or time()) + ttl

      collections.remove_range_by_score(self, name, aud_sub_key, 0, exp_score)
      collections.insert_element(self, name, aud_sub_key, key, new_score)
      if old_key then
        collections.delete_element(self, name, aud_sub_key, old_key)
      end
    end
  end
  return ok
end

---
-- Retrieve session data.
--
-- @function instance:get
-- @tparam  string     name cookie name
-- @tparam  string     key  session key
-- @treturn string|nil      session data
-- @treturn string          error message
function metatable:get(name, key)
  local _, res, err = run_worker_thread(
    self.pool,
    "resty.session.file-thread",
    "get",
    get_path(self, name, key)
  )
  return res, err
end


---
-- Delete session data.
--
-- @function instance:delete
-- @tparam  string      name cookie name
-- @tparam  string      key  session key
-- @tparam[opt]  table  metadata  session meta data
-- @treturn boolean|nil      session data
-- @treturn string           error message
function metatable:delete(name, key, metadata)
  run_worker_thread(
    self.pool,
    "resty.session.file-thread",
    "delete",
    get_path(self, name, key)
  )
  if not metadata then
    return true
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  local exp_score = time() - 1
  for i = 1, #audiences do
    local aud_sub_key = audiences[i] .. ":" .. subjects[i]
    collections.remove_range_by_score(self, name, aud_sub_key, 0, exp_score)
    collections.delete_element(self, name, aud_sub_key, key)
  end

  return true
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- File storage backend configuration
-- @field prefix file prefix for session file
-- @field suffix file suffix (or extension without `.`) for session file
-- @field pool name of the thread pool under which file writing happens (available on Linux only)
-- @field path path (or directory) under which session files are created
-- @table configuration


---
-- Constructors
-- @section constructors


---
-- Create a file storage.
--
-- This creates a new file storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  file storage @{configuration}
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
