---
-- File storage backend for session library.
--
-- @module resty.session.file


local file_utils  = require "resty.session.file.utils"
local utils = require "resty.session.utils"
local lfs = require "lfs"


local run_worker_thread = file_utils.run_worker_thread
local get_meta_el_val = utils.get_meta_el_val
local get_path_meta = file_utils.get_path_meta
local get_meta_key = utils.get_meta_key
local get_path = file_utils.get_path


local attributes = lfs.attributes
local touch = lfs.touch
local dir = lfs.dir


local setmetatable = setmetatable
local tonumber = tonumber
local random = math.random
local gmatch = string.gmatch
local error = error
local byte = string.byte
local find = string.find
local max = math.max
local sub = string.sub
local log = ngx.log


local SLASH_BYTE = byte("/")
local DEBUG = ngx.DEBUG


local TTL_CLEAN_PROBABILITY = 0.0002 -- 1 / 5000


local DEFAULT_POOL = "default"
local DEFAULT_SUFFIX = "ses"
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


local function file_get(pool, path)
  local ok, res, err = run_worker_thread(
    pool,
    "resty.session.file.thread",
    "get",
    path
  )

  if not ok then
    return nil, res
  end

  return res, err
end


local function file_set(pool, path, value)
  local ok, res, err = run_worker_thread(
    pool,
    "resty.session.file.thread",
    "set",
    path,
    value
  )

  if not ok then
    return nil, res
  end

  return res, err
end


local function file_delete(pool, path)
  local ok, res, err = run_worker_thread(
    pool,
    "resty.session.file.thread",
    "delete",
    path
  )

  if not ok then
    return nil, res
  end

  return res, err
end


local function file_append(pool, path, value)
  local ok, res, err = run_worker_thread(
    pool,
    "resty.session.file.thread",
    "append",
    path,
    value
  )

  if not ok then
    return nil, res
  end

  return res, err
end


-- note: this metadata is always appended to the specific aud:sub key
-- TODO: atomically trim the file to avoid infinite growth
local function update_sid_exp(storage, aud_sub_key, sid, exp, current_time)
  local meta_el = get_meta_el_val(sid, exp)
  if not meta_el then
    return
  end

  local pool = storage.pool
  local path = get_path_meta(storage, aud_sub_key)

  file_append(pool, path, meta_el)
  local attr = attributes(path)
  local curr_exp = attr and attr.modification or current_time
  local new_exp = max(curr_exp, exp)
  touch(path, nil, new_exp)
end


local function read_metadata(storage, audience, subject, current_time)
  local aud_sub_key = get_meta_key(storage, audience, subject)
  local path = get_path_meta(storage, aud_sub_key)
  local res = file_get(storage.pool, path)
  if not res then
    return nil, "not found"
  end

  local pattern = ".-:.-;"
  local sessions = {}

  for s in gmatch(res, pattern) do
    local i = find(s, ":", nil, true)
    local sid = sub(s, 1,  i - 1)
    local exp = sub(s, i + 1, #s - 1)
    exp = tonumber(exp)
    if exp > current_time then
      sessions[sid] = exp
    else
      sessions[sid] = nil
    end
  end

  return sessions
end


local function cleanup_check(storage, current_time)
  if random() > TTL_CLEAN_PROBABILITY then
    return false
  end

  local pool = storage.pool
  local path = storage.path
  local suffix = storage.suffix
  local deleted = 0

  log(DEBUG, "[session] expired keys cleanup initiated")

  for file in dir(path) do
    if file ~= "." and file ~= ".." then
      if #file > #suffix and file:sub(#file - #suffix + 1, #file) == suffix then
        local attr = attributes(path .. file)
        local exp = attr and attr.modification
        if exp < current_time then
          file = path .. file
          file_delete(pool, file)
          deleted = deleted + 1
        end
      end
    end
  end

  log(DEBUG, "[session] deleted ", deleted, " files")

  return true
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
  cleanup_check(self, current_time)

  local pool = self.pool
  local path = get_path(self, name, key)
  if not metadata and not old_key then
    local res, err = file_set(pool, path, value)
    -- use mtime to hold the value of the expiration time of the file (and session)
    if current_time and ttl then
      touch(path, nil, current_time + ttl)
    end
    return res, err
  end

  local old_ttl, old_path
  if old_key then
    old_path = get_path(self, name, old_key)
    if not remember then
      local attr = attributes(old_path)
      local exp = attr and attr.modification
      old_ttl = exp - current_time
    end
  end


  local res, err = file_set(pool, path, value)
  if not res then
    return nil, err or "set failed"
  end

  if current_time and ttl then
    touch(path, nil, current_time + ttl)
  end
  if old_path then
    if remember then
      file_delete(pool, old_path)
    elseif (not old_ttl or old_ttl > stale_ttl) then
      touch(old_path, nil, current_time + stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
      update_sid_exp(self, aud_sub_key, key, current_time + ttl, current_time)
      if old_key then
        update_sid_exp(self, aud_sub_key, old_key, 0, current_time)
      end
    end
  end

  return true
end


---
-- Retrieve session data.
--
-- @function instance:get
-- @tparam  string     name cookie name
-- @tparam  string     key  session key
-- @treturn string|nil      session data
-- @treturn string          error message
function metatable:get(name, key, current_time)
  local path = get_path(self, name, key)
  local attr = attributes(path)

  local exp = attr and attr.modification
  if exp and exp < current_time then
    return nil, "expired"
  end

  local res, err = file_get(self.pool, path)
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
function metatable:delete(name, key, current_time, metadata)
  cleanup_check(self, current_time)

  local pool = self.pool
  local path = get_path(self, name, key)
  file_delete(pool, path)
  if not metadata then
    return true
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  for i = 1, #audiences do
    local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
    update_sid_exp(self, aud_sub_key, key, 0, current_time)
  end

  return true
end


function metatable:read_metadata(audience, subject, current_time)
  return read_metadata(self, audience, subject, current_time)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- File storage backend configuration
-- @field prefix File prefix for session file.
-- @field suffix File suffix (or extension without `.`) for session file.
-- @field pool Name of the thread pool under which file writing happens (available on Linux only).
-- @field path Path (or directory) under which session files are created.
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
  local suffix = configuration and configuration.suffix or DEFAULT_SUFFIX

  local pool   = configuration and configuration.pool   or DEFAULT_POOL
  local path   = configuration and configuration.path   or DEFAULT_PATH

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
