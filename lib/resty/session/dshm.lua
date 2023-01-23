---
-- Distributed Shared Memory (DSHM) backend for session library
--
-- @module resty.session.dshm


local dshm        = require "resty.dshm"
local buffer      = require "string.buffer"
local utils       = require "resty.session.utils"

local get_meta_key     = utils.get_meta_key
local get_meta_el_val  = utils.get_meta_el_val
local get_latest_valid = utils.get_latest_valid
local setmetatable     = setmetatable
local error            = error
local null             = ngx.null
local get_name         = utils.get_name


-- not safe for concurrent access
local function update_sid_exp(dshmc, aud_sub_key, sid, exp, now)
  local max_exp = now

  local res = dshmc:get(aud_sub_key)
  local sessions = get_latest_valid(res, now)
  local buf = buffer.new()

  sessions[sid] = exp > 0 and exp or nil
  for s, e in pairs(sessions) do
    buf = buf:put(get_meta_el_val(s, e))
    max_exp = math.max(max_exp, e)
  end

  local ser = buf:tostring()
  if #ser > 0 then
    return dshmc:set(aud_sub_key, ser, max_exp - now)
  else
    return dshmc:delete(aud_sub_key)
  end
end

local function READ_METADATA(self, dshmc, audience, subject)
  local pattern     = ".-:.-;"
  local sessions    = {}

  local aud_sub_key = get_meta_key(self, audience, subject)
  local res         = dshmc:get(aud_sub_key)
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

local function SET(self, dshmc, name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  local inferred_key = get_name(self, name, key)

  if not metadata and not old_key then
    return dshmc:set(inferred_key, value, ttl)
  end

  local ok, err = dshmc:set(inferred_key, value, ttl)
  if err then
    return nil, err
  end

  local old_name = old_key and get_name(self, name, old_key)
  if old_name then
    if remember then
      dshmc:delete(old_name)
    else
      dshmc:touch(old_name, stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
      update_sid_exp(dshmc, aud_sub_key, key, current_time + ttl, current_time)

      if old_key then
        update_sid_exp(dshmc, aud_sub_key, old_key, 0, current_time)
      end
    end
  end
  return ok
end

local function GET(self, dshmc, name, key)
  local res, err = dshmc:get(get_name(self, name, key))
  if err then
    return nil, err
  end
  return res
end

local function DELETE(self, dshmc, name, key, metadata, current_time)
  local key_name = get_name(self, name, key)
  local ok, err = dshmc:delete(key_name)

  if not metadata then
    return ok
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  for i = 1, #audiences do
    local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
    update_sid_exp(dshmc, aud_sub_key, key, 0, current_time)
  end

  return ok, err
end

local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 4321


local function exec(self, func, ...)
  local dshmc = dshm:new()
  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
      dshmc.sock:settimeouts(connect_timeout, send_timeout, read_timeout)
  end

  local ok, err = dshmc:connect(self.host, self.port, self.options)
  if not ok then
    return nil, err
  end

  if self.ssl and dshmc:get_reused_times() == 0 then
    ok, err = dshmc.sock:sslhandshake(false, self.server_name, self.ssl_verify)
    if not ok then
      dshmc:close()
      return nil, err
    end
  end

  ok, err = func(self, dshmc, ...)
  if err then
    dshmc:close()
    return nil, err
  end

  if not dshmc:set_keepalive(self.keepalive_timeout) then
    dshmc:close()
  end

  if ok == null then
    ok = nil
  end

  return ok, err
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
function metatable:set(...)
  return exec(self, SET, ...)
end


---
-- Retrieve session data.
--
-- @function instance:get
-- @tparam  string     name cookie name
-- @tparam  string     key  session key
-- @treturn string|nil      session data
-- @treturn string          error message
function metatable:get(...)
  return exec(self, GET, ...)
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
function metatable:delete(...)
  return exec(self, DELETE, ...)
end


function metatable:read_metadata(...)
  return exec(self, READ_METADATA, ...)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- Distributed shared memory storage backend configuration
-- @field prefix prefix for the keys stored in DSHM
-- @field suffix suffix for the keys stored in DSHM
-- @field host the host to connect (defaults to `"127.0.0.1"`)
-- @field port the port to connect (defaults to `4321`)
-- @field connect_timeout controls the default timeout value used in TCP/unix-domain socket object's `connect` method
-- @field send_timeout controls the default timeout value used in TCP/unix-domain socket object's `send` method
-- @field read_timeout controls the default timeout value used in TCP/unix-domain socket object's `receive` method
-- @field keepalive_timeout controls the default maximal idle time of the connections in the connection pool
-- @field pool a custom name for the connection pool being used.
-- @field pool_size the size of the connection pool,
-- @field backlog a queue size to use when the connection pool is full (configured with @pool_size)
-- @field ssl enable ssl (defaults to `false`)
-- @field ssl_verify verify server certificate (defaults to `nil`)
-- @field server_name the server name for the new TLS extension Server Name Indication (SNI)
-- @table configuration


---
-- Constructors
-- @section constructors


---
-- Create a distributed shared memory storage.
--
-- This creates a new distributed shared memory storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  DSHM storage @{configuration}
-- @treturn      table                  DSHM storage instance
function storage.new(configuration)
  local prefix            = configuration and configuration.prefix
  local suffix            = configuration and configuration.suffix

  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT

  local connect_timeout   = configuration and configuration.connect_timeout
  local send_timeout      = configuration and configuration.send_timeout
  local read_timeout      = configuration and configuration.read_timeout
  local keepalive_timeout = configuration and configuration.keepalive_timeout

  local pool              = configuration and configuration.pool
  local pool_size         = configuration and configuration.pool_size
  local backlog           = configuration and configuration.backlog
  local ssl               = configuration and configuration.ssl
  local ssl_verify        = configuration and configuration.ssl_verify
  local server_name       = configuration and configuration.server_name

  if pool or pool_size or backlog then
    setmetatable({
      prefix = prefix,
      suffix = suffix,
      host = host,
      port = port,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      ssl = ssl,
      ssl_verify = ssl_verify,
      server_name = server_name,
      options = {
        pool = pool,
        pool_size = pool_size,
        backlog = backlog,
      }
    }, metatable)
  end

  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    host = host,
    port = port,
    connect_timeout = connect_timeout,
    send_timeout = send_timeout,
    read_timeout = read_timeout,
    keepalive_timeout = keepalive_timeout,
    ssl = ssl,
    ssl_verify = ssl_verify,
    server_name = server_name,
  }, metatable)
end


return storage
