---
-- Shared Memory (SHM) backend for session library
--
-- @module resty.session.shm


local get_name = require "resty.session.utils".get_name


local setmetatable = setmetatable
local shared = ngx.shared
local assert = assert
local error = error


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
  local ok, err = self.dict:set(get_name(self, name, key), value, ttl)
  if not ok then
    return nil, err
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
function metatable:get(name, key)
  local value, err = self.dict:get(get_name(self, name, key))
  if not value then
    return nil, err
  end
  return value
end


-- TODO: needs to be removed (set command should do it)
function metatable:ttl(name, key)
  local ttl, err = self.dict:ttl(get_name(self, name, key))
  if not ttl then
    return nil, err
  end
  return ttl
end


-- TODO: needs to be removed (set command should do it)
function metatable:expire(name, key, ttl)
  local ok, err = self.dict:expire(get_name(self, name, key), ttl)
  if not ok then
    return nil, err
  end
  return true
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
