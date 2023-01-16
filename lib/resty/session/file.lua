---
-- File storage backend for session library.
--
-- @module resty.session.file

local lfs         = require "lfs"
local collections = require "resty.session.scored-collections"
local file_utils  = require "resty.session.file.file-utils"
local utils       = require "resty.session.utils"

local run_worker_thread = file_utils.run_worker_thread
local should_cleanup = utils.should_cleanup
local get_path = file_utils.get_path
local setmetatable = setmetatable
local byte = string.byte
local time = ngx.time
local error = error


local SLASH_BYTE = byte("/")

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


local function cleanup(storage)
  if not should_cleanup() then
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
          ngx.log(ngx.ERR, "deleting file "..file)
          file = path .. file
          run_worker_thread(
            storage.pool,
            "resty.session.file.file-thread",
            "delete",
            file
          )
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
  cleanup(self)
  local path = get_path(self, name, key)
  if not metadata and not old_key then
    local _, res, err = run_worker_thread(
      self.pool,
      "resty.session.file.file-thread",
      "set",
      path,
      value
    )
    -- use mtime to hold the value of the expiration time of the file (and session)
    if current_time and ttl then
      lfs.touch(path, nil, current_time + ttl)
    end
    return res, err
  end

  local old_ttl, old_path
  if old_key then
    if not remember then
      old_path = get_path(self, name, old_key)
      local attr = lfs.attributes(old_path)
      local exp = attr and attr.modification
      old_ttl = exp - current_time
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

  if current_time and ttl then
    lfs.touch(path, nil, current_time + ttl)
  end
  if old_path then
    if remember then
      run_worker_thread(
        self.pool,
        "resty.session.file.file-thread",
        "delete",
        old_path
      )
    elseif (not old_ttl or old_ttl > stale_ttl) then
      lfs.touch(old_path, nil, current_time + stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = audiences[i] .. "_" .. subjects[i]
      local exp_score   = (current_time or time()) - 1
      local new_score   = (current_time or time()) + ttl

      collections.remove_range_by_score(self, name, aud_sub_key, exp_score)
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
  local now  = time()
  local path = get_path(self, name, key)

  local attr = lfs.attributes(path)
  local exp = attr and attr.modification

  if exp and exp < now then
    return nil, "expired"
  end

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
  cleanup(self)
  local path = get_path(self, name, key)

  run_worker_thread(
    self.pool,
    "resty.session.file.file-thread",
    "delete",
    path
  )
  if not metadata then
    return true
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  local exp_score = time() - 1
  for i = 1, #audiences do
    local aud_sub_key = audiences[i] .. "_" .. subjects[i]
    collections.remove_range_by_score(self, name, aud_sub_key, exp_score)
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
