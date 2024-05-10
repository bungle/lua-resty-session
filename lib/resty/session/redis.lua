---
-- Redis backend for session library
--
-- @module resty.session.redis


local utils = require "resty.session.utils"
local common = require "resty.session.redis.common"
local redis = require "resty.redis"


local setmetatable = setmetatable
local error = error
local tostring = tostring
local assert = assert

local null = ngx.null
local rand_bytes = utils.rand_bytes


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 6379
local DEFAULT_DATABASE = 0

local KEY_SIZE = 32
local DEFAULT_IKM = rand_bytes(KEY_SIZE)
local DEFAULT_NONCE = rand_bytes(KEY_SIZE)


local SET = common.SET
local GET = common.GET
local UNLINK = common.UNLINK
local READ_METADATA = common.READ_METADATA


local get_pool do
  local mac_sha256 = utils.mac_sha256
  local derive_hmac_sha256_key = utils.derive_hmac_sha256_key

  --- get connection pool name for the current session
  -- must ensure the pool name of a session is unique for
  -- each combination of host, port, database and password
  get_pool = function(config)
    local opts = config or {}
    local mac do
      if opts.password then
        local key, err = derive_hmac_sha256_key(opts.ikm, opts.nonce)
        if not key then
          return nil, err
        end

        mac, err = mac_sha256(key, tostring(opts.password))
        if not mac then
          return nil, err
        end
      end
    end

    --- examples
    -- with password: foo:redis-ssl-auth:6379:0:default:de0d22d975dcc57a721171fa079aa54a788df759c4a68ae75fd5f26c5490c9ca:true:false:redis:bar
    -- without password: foo:redis-ssl-auth:6379:0:default::false:false:redis:bar
    return (opts.prefix or "") .. ":" ..
           (opts.host or "") .. ":" ..
           (tostring(opts.port) or "") .. ":" ..
           (tostring(opts.database) or "") .. ":" ..
           (opts.username or "default") .. ":" ..
           (mac or "") .. ":" ..
           (tostring(opts.ssl) or "") .. ":" ..
           (tostring(opts.ssl_verify) or "") .. ":" ..
           (opts.server_name or "") .. ":" ..
           (opts.suffix or "")
  end
end


local function exec(self, func, ...)
  local red = redis:new()

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    red:set_timeouts(connect_timeout, send_timeout, read_timeout)
  end

  local ok, err do
    local socket = self.socket
    -- ngx.log(ngx.NOTICE, "pool_name = ", self.options.pool)
    if socket then
      ok, err = red:connect(socket, self.options)
    else
      ok, err = red:connect(self.host, self.port, self.options)
    end
  end
  if not ok then
    return nil, err
  end

  if red:get_reused_times() == 0 then
    local password = self.password
    if password then
      local username = self.username
      if username then
        ok, err = red:auth(username, password)
      else
        ok, err = red:auth(password)
      end

      if not ok then
        red:close()
        return nil, err
      end
    end

    --- select database for new connection in case
    -- there is no need to select before every Redis
    -- operation as the connection pool is only shared
    -- clients that use the same database
    ok, err = red:select(self.database)
    if not ok then
      return nil, err
    end
  end

  ok, err = func(self, red, ...)
  if err then
    red:close()
    return nil, err
  end

  if not red:set_keepalive(self.keepalive_timeout) then
    red:close()
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
-- @tparam string name cookie name
-- @tparam string key session key
-- @tparam string value session value
-- @tparam number ttl session ttl
-- @tparam number current_time current time
-- @tparam[opt] string old_key old session id
-- @tparam string stale_ttl stale ttl
-- @tparam[opt] table metadata table of metadata
-- @tparam boolean remember whether storing persistent session or not
-- @treturn true|nil ok
-- @treturn string error message
function metatable:set(...)
  return exec(self, SET, ...)
end


---
-- Retrieve session data.
--
-- @function instance:get
-- @tparam string name cookie name
-- @tparam string key session key
-- @treturn string|nil session data
-- @treturn string error message
function metatable:get(...)
  return exec(self, GET, ...)
end


---
-- Delete session data.
--
-- @function instance:delete
-- @tparam string name cookie name
-- @tparam string key session key
-- @tparam[opt] table metadata session meta data
-- @treturn boolean|nil session data
-- @treturn string error message
function metatable:delete(...)
  return exec(self, UNLINK, ...)
end


---
-- Read session metadata.
--
-- @function instance:read_metadata
-- @tparam string name cookie name
-- @tparam string audience session key
-- @tparam string subject session key
-- @tparam number current_time current time
-- @treturn table|nil session metadata
-- @treturn string error message
function metatable:read_metadata(...)
  return exec(self, READ_METADATA, ...)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- Redis storage backend configuration
-- @field prefix Prefix for the keys stored in Redis.
-- @field suffix Suffix for the keys stored in Redis.
-- @field host The host to connect (defaults to `"127.0.0.1"`).
-- @field port The port to connect (defaults to `6379`).
-- @field socket The socket file to connect to (defaults to `nil`).
-- @field username The database username to authenticate.
-- @field password Password for authentication.
-- @field database The database to connect.
-- @field connect_timeout Controls the default timeout value used in TCP/unix-domain socket object's `connect` method.
-- @field send_timeout Controls the default timeout value used in TCP/unix-domain socket object's `send` method.
-- @field read_timeout Controls the default timeout value used in TCP/unix-domain socket object's `receive` method.
-- @field keepalive_timeout Controls the default maximal idle time of the connections in the connection pool.
-- @field pool A custom name for the connection pool being used.
-- @field pool_size The size of the connection pool.
-- @field backlog A queue size to use when the connection pool is full (configured with @pool_size).
-- @field ssl Enable SSL (defaults to `false`).
-- @field ssl_verify Verify server certificate (defaults to `nil`).
-- @field server_name The server name for the new TLS extension Server Name Indication (SNI).
-- @table configuration


---
-- Constructors
-- @section constructors


---
-- Create a Redis storage.
--
-- This creates a new Redis storage instance.
--
-- @function module.new
-- @tparam[opt] table configuration redis storage @{configuration}
-- @treturn table redis storage instance
function storage.new(configuration)
  local prefix            = configuration and configuration.prefix
  local suffix            = configuration and configuration.suffix

  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT
  local socket            = configuration and configuration.socket

  local username          = configuration and configuration.username
  local password          = configuration and configuration.password
  local database          = configuration and configuration.database or DEFAULT_DATABASE

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

  local ikm               = configuration and configuration.ikm

  if ikm then
    assert(#ikm == KEY_SIZE, "ikm size must be " .. KEY_SIZE)
  end
  local meta = {
    ikm = ikm or DEFAULT_IKM,
    nonce = DEFAULT_NONCE,
  }
  if not pool then
    pool = get_pool {
      host = host,
      port = port,
      database = database,
      username = username,
      password = password,
      ssl = ssl,
      ssl_verify = ssl_verify,
      server_name = server_name,
      ikm = meta.ikm,
      nonce = meta.nonce,
      prefix = prefix,
      suffix = suffix,
    }
  end

  if ssl ~= nil or ssl_verify ~= nil or server_name or pool or pool_size or backlog then
    return setmetatable({
      prefix = prefix,
      suffix = suffix,
      host = host,
      port = port,
      socket = socket,
      username = username,
      password = password,
      database = database,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      options = {
        ssl = ssl,
        ssl_verify = ssl_verify,
        server_name = server_name,
        pool = pool,
        pool_size = pool_size,
        backlog = backlog,
      },
      meta = meta,
    }, metatable)
  end

  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    host = host,
    port = port,
    socket = socket,
    username = username,
    password = password,
    database = database,
    connect_timeout = connect_timeout,
    send_timeout = send_timeout,
    read_timeout = read_timeout,
    keepalive_timeout = keepalive_timeout,
    options = {
      pool = pool,
    },
    meta = meta,
  }, metatable)
end


return storage
