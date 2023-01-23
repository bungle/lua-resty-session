---
-- File storage backend for session library.
--
-- @module resty.session.file

local lfs         = require "lfs"
local file_utils  = require "resty.session.file.utils"
local buffer      = require "string.buffer"
local utils       = require "resty.session.utils"

local run_worker_thread = file_utils.run_worker_thread
local get_latest_valid = utils.get_latest_valid
local get_meta_el_val  = utils.get_meta_el_val
local get_path_meta = file_utils.get_path_meta
local get_meta_key     = utils.get_meta_key
local get_path = file_utils.get_path

local setmetatable = setmetatable
local random = math.random
local byte = string.byte
local time = ngx.time
local error = error


local SLASH_BYTE = byte("/")
-- 1/5000
local CLEANUP_PROBABILITY = 0.0002

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

local function file_get(storage, path)
  local ok, res, err = run_worker_thread(
    storage.pool,
    "resty.session.file.thread",
    "get",
    path
  )
  return ok, res, err
end

local function file_set(storage, path, value)
  local ok, res, err = run_worker_thread(
    storage.pool,
    "resty.session.file.thread",
    "set",
    path,
    value
  )
  return ok, res, err
end

local function file_delete(storage, path)
  run_worker_thread(
    storage.pool,
    "resty.session.file.thread",
    "delete",
    path
  )
end

-- not safe for concurrent access
-- updates sid:exp; in the metadata of the audience/subject
local function update_sid_exp(storage, aud_sub_key, sid, exp, now)
  local max_exp  = now
  local path     = get_path_meta(storage, aud_sub_key)
  local _, res   = file_get(storage, path)
  local sessions = get_latest_valid(res, now)
  local buf      = buffer.new()

  sessions[sid] = exp > 0 and exp or nil
  for s, e in pairs(sessions) do
    buf = buf:put(get_meta_el_val(s, e))
    max_exp = math.max(max_exp, e)
  end

  local ser = buf:tostring()
  if #ser > 0 then
    file_set(storage, path, ser)
    lfs.touch(path, nil, max_exp)
  else
    file_delete(storage, path)
  end
end

local function read_metadata(storage, audience, subject)
  local pattern     = ".-:.-;"
  local sessions    = {}

  local aud_sub_key = get_meta_key(storage, audience, subject)
  local path        = get_path_meta(storage, aud_sub_key)
  local _, res      = file_get(storage, path)
  if not res then
    return nil, "not found"
  end

  for s in string.gmatch(res, pattern) do
    local i = string.find(s, ":")
    local sid = string.sub(s,     1,  i - 1)
    local exp = string.sub(s, i + 1, #s - 1)
    exp = tonumber(exp)
    sessions[sid] = exp
  end

  return sessions
end

local function cleanup_check(storage)
  if random() > CLEANUP_PROBABILITY then
    return false
  end
  local now     = time()
  local path    = storage.path
  local suffix  = storage.suffix
  local deleted = 0

  ngx.log(ngx.DEBUG, "expired keys cleanup initiated")

  for file in lfs.dir(path) do
    if file ~= "." and file ~= ".." then
      if #file > #suffix and file:sub(#file - #suffix + 1, #file) == suffix then
        local attr = lfs.attributes(path .. file)
        local exp = attr and attr.modification
        if exp < now then
          file = path .. file
          file_delete(storage, file)
          deleted = deleted + 1
        end
      end
    end
  end
  ngx.log(ngx.DEBUG, string.format("deleted %s files", deleted))
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
  cleanup_check(self)
  local path = get_path(self, name, key)
  if not metadata and not old_key then
    local _, res, err = file_set(self, path, value)
    -- use mtime to hold the value of the expiration time of the file (and session)
    if current_time and ttl then
      lfs.touch(path, nil, current_time + ttl)
    end
    return res, err
  end

  local old_ttl, old_path
  if old_key then
    old_path = get_path(self, name, old_key)
    if not remember then
      local attr = lfs.attributes(old_path)
      local exp = attr and attr.modification
      old_ttl = exp - current_time
    end
  end


  local ok, res, err = file_set(self, path, value)
  if not res then
    return nil, err or "set failed"
  end

  if current_time and ttl then
    lfs.touch(path, nil, current_time + ttl)
  end
  if old_path then
    if remember then
      file_delete(self, old_path)
    elseif (not old_ttl or old_ttl > stale_ttl) then
      lfs.touch(old_path, nil, current_time + stale_ttl)
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
  local now  = time()
  local path = get_path(self, name, key)

  local attr = lfs.attributes(path)
  local exp = attr and attr.modification

  if exp and exp < now then
    return nil, "expired"
  end

  local _, res, err = file_get(self, path)
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
function metatable:delete(name, key, metadata, current_time)
  cleanup_check(self)
  local path = get_path(self, name, key)

  file_delete(self, path)
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

function metatable:read_metadata(audience, subject)
  return read_metadata(self, audience, subject)
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
  local suffix = configuration and configuration.suffix or DEFAULT_SUFFIX

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
