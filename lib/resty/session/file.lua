---
-- File storage backend for session library.
--
-- @module resty.session.file


local collections = require "resty.session.scored-collections"
local file_utils  = require "resty.session.file.file-utils"
local EXP         = require "resty.session.file.file-expirations"

local setmetatable = setmetatable
local error = error
local byte = string.byte
local time = ngx.time
local run_worker_thread = file_utils.run_worker_thread
local get_path = file_utils.get_path


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
  local now = (current_time or time())
  EXP.delete_expired(self, name, now, false)

  local path = get_path(self, name, key)
  if not metadata and not old_key then
    if ttl then
      EXP.upsert_ttl(self, name, key, ttl, now)
    end
    local _, res, err = run_worker_thread(
      self.pool,
      "resty.session.file.file-thread",
      "set",
      path,
      value
    )
    return res, err
  end

  local old_ttl
  if old_key then
    if not remember then
      old_ttl = EXP.expires_at(self, name, old_key)
    end
  end

  local ok, res, err = run_worker_thread(
    self.pool,
    "resty.session.file.file-thread",
    "set",
    path,
    value
  )
  if not res then
    return nil, err or "set failed"
  end
  if ttl then
    EXP.upsert_ttl(self, name, key, ttl, now)
  end

  if old_key then
    if remember then
      run_worker_thread(
        self.pool,
        "resty.session.file.file-thread",
        "delete",
        path
      )
    elseif (not old_ttl or old_ttl > stale_ttl) then
      EXP.upsert_ttl(self, name, old_key, stale_ttl, now)
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
  local now = time()
  EXP.delete_expired(self, name, now, true)

  local _, res, err = run_worker_thread(
    self.pool,
    "resty.session.file.file-thread",
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
  local ses_path = get_path(self, name, key)
  local now = time()

  EXP.delete_expired(self, name, now, false)
  EXP.remove_file(self, name, key, true)

  run_worker_thread(
    self.pool,
    "resty.session.file.file-thread",
    "delete",
    ses_path
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
