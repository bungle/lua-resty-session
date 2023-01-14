---
-- Shared Memory (SHM) backend for session library
--
-- @module resty.session.shm


local get_name    = require "resty.session.utils".get_name
local collections = require "resty.session.scored-collections"


local setmetatable = setmetatable
local shared = ngx.shared
local assert = assert
local error = error
local time = ngx.time


local DEFAULT_ZONE = "sessions"


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
function metatable:delete(name, key, metadata)
  self.dict:delete(get_name(self, name, key))
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
-- Shared memory storage backend configuration
-- @field prefix prefix for the keys stored in SHM
-- @field suffix suffix for the keys stored in SHM
-- @field zone a name of shared memory zone (defaults to `sessions`)
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
