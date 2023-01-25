---
-- Shared Memory (SHM) backend for session library
--
-- @module resty.session.shm


local utils  = require "resty.session.utils"


local meta_get_next_sid_exp = utils.meta_get_next_sid_exp
local meta_get_el_val = utils.meta_get_el_val
local meta_get_key = utils.meta_get_key
local get_name = utils.get_name


local setmetatable = setmetatable
local shared = ngx.shared
local random = math.random
local assert = assert
local error = error
local pairs = pairs
local max = math.max


local DEFAULT_ZONE = "sessions"
local CLEANUP_PROBABILITY = 0.1 -- 1 / 10


local function keep_latest_valid(dict, aud_sub_key, current_time, preserve_el)
  local size    = dict:llen(aud_sub_key)
  local max_exp = current_time
  local sess    = {}

  for _ = 1, size do
    local el = dict:lpop(aud_sub_key)
    if not el then
      break
    end

    local sid, err, exp = meta_get_next_sid_exp(el, 1)
    if err then
      return nil, err
    end

    if exp and exp > current_time then
      sess[sid] = exp
      max_exp = max(max_exp, exp)
    else
      sess[sid] = nil
    end
  end

  if preserve_el then
    for sid, exp in pairs(sess) do
      local el = meta_get_el_val(sid, exp)
      dict:rpush(aud_sub_key, el)
    end
  end

  dict:expire(aud_sub_key, max_exp - current_time)
  return sess
end


local function metadata_cleanup(self, aud_sub_key, current_time)
  local dict = self.dict
  keep_latest_valid(dict, aud_sub_key, current_time, true)
end


local function read_metadata(self, aud_sub_key, current_time)
  return keep_latest_valid(self.dict, aud_sub_key, current_time, true)
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
  if not metadata and not old_key then
    local ok, err = self.dict:set(get_name(self, name, key), value, ttl)
    if not ok then
      return nil, err
    end
    return true
  end

  local old_name, old_ttl
  if old_key then
    old_name = get_name(self, name, old_key)
    if not remember then
      old_ttl = self.dict:ttl(old_name)
    end
  end

  local ok, err = self.dict:set(get_name(self, name, key), value, ttl)
  if not ok then
    return nil, err
  end

  if old_name then
    if remember then
      self.dict:delete(old_name)
    elseif (not old_ttl or old_ttl > stale_ttl) then
      self.dict:expire(old_name, stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = meta_get_key(self, name, audiences[i], subjects[i])
      local meta_el_val = meta_get_el_val(key, current_time + ttl)

      ok, err = self.dict:rpush(aud_sub_key, meta_el_val)

      if old_key then
        meta_el_val = meta_get_el_val(old_key, 0)
        ok, err = self.dict:rpush(aud_sub_key, meta_el_val)
      end
      -- no need to clean up every time we write
      -- it is just beneficial when a key is used a lot
      if random() < CLEANUP_PROBABILITY then
        metadata_cleanup(self, aud_sub_key, current_time)
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
  local value, err = self.dict:get(get_name(self, name, key))
  if not value then
    return nil, err
  end
  return value
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
  self.dict:delete(get_name(self, name, key))
  if not metadata then
    return true
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  for i = 1, #audiences do
    local aud_sub_key = meta_get_key(self, name, audiences[i], subjects[i])
    local meta_el_val = meta_get_el_val(key, 0)
    self.dict:rpush(aud_sub_key, meta_el_val)
    metadata_cleanup(self, aud_sub_key, current_time)
  end

  return true
end


function metatable:read_metadata(name, audience, subject, current_time)
  local aud_sub_key = meta_get_key(self, name, audience, subject)
  return read_metadata(self, aud_sub_key, current_time)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- Shared memory storage backend configuration
-- @field prefix Prefix for the keys stored in SHM.
-- @field suffix Suffix for the keys stored in SHM.
-- @field zone A name of shared memory zone (defaults to `sessions`).
-- @table configuration


---
-- Constructors
-- @section constructors


---
-- Create a SHM storage.
--
-- This creates a new shared memory storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  shm storage @{configuration}
-- @treturn      table                  shm storage instance
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
