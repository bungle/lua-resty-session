---
-- Memcached backend for session library
--
-- @module resty.session.memcached


local memcached   = require "resty.memcached"
local utils       = require "resty.session.utils"
local buffer      = require "string.buffer"


local setmetatable = setmetatable
local error        = error
local null         = ngx.null
local time         = ngx.time
local get_name     = utils.get_name
local get_meta_key = utils.get_meta_key
local get_meta_el_val = utils.get_meta_el_val
local get_latest_valid = utils.get_latest_valid


local function metadata_cleanup(self, memc, aud_sub_key)
  local now     = time()
  local retry   = 10
  local max_exp = now
  local ok      = false

  while(retry > 0 and not ok) do
    retry = retry - 1
    local res, _, cas_u, err = memc:gets(aud_sub_key)
    if not res then
      return nil, err
    end

    local sessions = get_latest_valid(res)
    local buf  = buffer.new()

    for s, exp in pairs(sessions) do
      buf = buf:put(get_meta_el_val(s, exp))
      max_exp = math.max(max_exp, exp)
    end

    ok, err = memc:cas(aud_sub_key, buf:tostring(), cas_u, max_exp - now)
  end
  return ok
end

local function read_metadata(self, memc, audience, subject)
  local aud_sub_key = get_meta_key(self, audience, subject)
  local res, _, err = memc:get(aud_sub_key)
  if not res then
    return nil, err
  end

  return get_latest_valid(res)
end

local function SET(self, memc, name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  local inferred_key = get_name(self, name, key)

  if not metadata and not old_key then
    return memc:set(inferred_key, value, ttl)
  end

  local ok, err = memc:set(inferred_key, value, ttl)
  if err then
    return nil, err
  end

  local old_name = old_key and get_name(self, name, old_key)
  if old_name then
    if remember then
      memc:delete(old_name)
    else
      memc:touch(old_name, stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    for i = 1, #audiences do
      local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
      local meta_el_val = get_meta_el_val(key, current_time + ttl)
      ok, err = memc:add(aud_sub_key, meta_el_val)
      if not ok then
        ok, err = memc:append(aud_sub_key, meta_el_val)
      end
      if old_key then
        meta_el_val = get_meta_el_val(old_key, 0)
        ok, err = memc:append(aud_sub_key, meta_el_val)
      end
      -- no need to clean up every time we write
      -- it is just beneficial when a key is used a lot
      if math.random() < 0.1 then
        metadata_cleanup(self, memc, aud_sub_key)
      end
    end
  end
  return ok
end

local function GET(self, memc, name, key)
  local res, _, err = memc:get(get_name(self, name, key))
  if err then
    return nil, err
  end
  return res
end

local function DELETE(self, memc, name, key, metadata)
  local key_name = get_name(self, name, key)
  local ok, err = memc:delete(key_name)

  if not metadata then
    return ok
  end

  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  for i = 1, #audiences do
    local aud_sub_key = get_meta_key(self, audiences[i], subjects[i])
    local meta_el_val = get_meta_el_val(key, 0)
    memc:append(aud_sub_key, meta_el_val)
    metadata_cleanup(self, memc, aud_sub_key)
  end

  return ok, err
end

local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 11211


local function exec(self, func, ...)
  local memc = memcached:new()

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    memc:set_timeouts(connect_timeout, send_timeout, read_timeout)
  end

  local ok, err do
    local socket = self.socket
    if socket then
      ok, err = memc:connect(socket, self.options)
    else
      ok, err = memc:connect(self.host, self.port, self.options)
    end
  end
  if not ok then
    return nil, err
  end

  if self.ssl and memc:get_reused_times() == 0 then
    ok, err = memc:sslhandshake(false, self.server_name, self.ssl_verify)
    if not ok then
      memc:close()
      return nil, err
    end
  end

  ok, err = func(self, memc, ...)

  if err then
    memc:close()
    return nil, err
  end

  if not memc:set_keepalive(self.keepalive_timeout) then
    memc:close()
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
function metatable:delete(...)--name, key, metadata)
  return exec(self, DELETE, ...)
end


function metatable:read_metadata(...)
  return exec(self, read_metadata, ...)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- Distributed shared memory storage backend configuration
-- @field prefix prefix for the keys stored in memcached
-- @field suffix suffix for the keys stored in memcached
-- @field host the host to connect (defaults to `"127.0.0.1"`)
-- @field port the port to connect (defaults to `11211`)
-- @field socket the socket file to connect to (defaults to `nil`)
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
-- Create a memcached storage.
--
-- This creates a new memcached storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  memcached storage @{configuration}
-- @treturn      table                  memcached storage instance
function storage.new(configuration)
  local prefix            = configuration and configuration.prefix
  local suffix            = configuration and configuration.suffix

  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT
  local socket            = configuration and configuration.socket

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
      socket = socket,
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
    socket = socket,
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
