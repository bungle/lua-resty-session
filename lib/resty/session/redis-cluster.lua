---
-- Redis Cluster backend for session library
--
-- @module resty.session.redis-cluster


local redis = require "resty.rediscluster"
local redis_common = require "resty.session.redis-common"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET           = redis_common.SET
local GET           = redis_common.GET
local UNLINK        = redis_common.UNLINK
local READ_METADATA = redis_common.READ_METADATA


local function exec(self, func, ...)
  local red, err = redis:new(self.options)
  if err then
    return nil, err
  end

  local ok, err = func(self, red, ...)
  if err then
    red:close()
    return nil, err
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
  return exec(self, UNLINK, ...)
end

function metatable:read_metadata(...)
  return exec(self, READ_METADATA, ...)
end

local storage = {}


---
-- Configuration
-- @section configuration


---
-- Redis Cluster storage backend configuration
-- @field prefix prefix for the keys stored in redis
-- @field suffix suffix for the keys stored in redis
-- @field name redis cluster name
-- @field nodes redis cluster nodes
-- @field lock_zone shared dictionary name for locks
-- @field lock_prefix shared dictionary name prefix for lock
-- @field max_redirections maximum retry attempts for redirection
-- @field max_connection_attempts maximum retry attempts for connection
-- @field max_connection_timeout maximum connection timeout in total among the retries
-- @field username the database username to authenticate
-- @field password password for authentication
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
-- Cluster Nodes
--
-- An array of cluster nodes.
--
-- @table nodes


---
-- Cluster Node
-- @field ip the ip address to connect (defaults to `"127.0.0.1"`)
-- @field port the port to connect (defaults to `6379`)
-- @table node


---
-- Constructors
-- @section constructors


---
-- Create a Redis Cluster storage.
--
-- This creates a new Redis Cluster storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  redis cluster storage @{configuration}
-- @treturn      table                  redis cluster storage instance
function storage.new(configuration)
  local prefix                  = configuration and configuration.prefix
  local suffix                  = configuration and configuration.suffix

  local name                    = configuration and configuration.name
  local nodes                   = configuration and configuration.nodes

  local lock_zone               = configuration and configuration.lock_zone
  local lock_prefix             = configuration and configuration.lock_prefix
  local max_redirections        = configuration and configuration.max_redirections
  local max_connection_attempts = configuration and configuration.max_connection_attempts
  local max_connection_timeout  = configuration and configuration.max_connection_timeout

  local username                = configuration and configuration.username
  local password                = configuration and configuration.password

  local connect_timeout         = configuration and configuration.connect_timeout
  local send_timeout            = configuration and configuration.send_timeout
  local read_timeout            = configuration and configuration.read_timeout
  local keepalive_timeout       = configuration and configuration.keepalive_timeout

  local pool                    = configuration and configuration.pool
  local pool_size               = configuration and configuration.pool_size
  local backlog                 = configuration and configuration.backlog
  local ssl                     = configuration and configuration.ssl
  local ssl_verify              = configuration and configuration.ssl_verify
  local server_name             = configuration and configuration.server_name

  local auth
  if password then
    if username then
      auth = username .. " " .. password
    else
      auth = password
    end
  end

  if ssl ~= nil or ssl_verify ~= nil or server_name or pool or pool_size or backlog then
    return setmetatable({
      prefix = prefix,
      suffix = suffix,
      options = {
        name = name,
        dict_name = lock_zone,
        refresh_lock_key = lock_prefix,
        serv_list = nodes,
        connect_timeout = connect_timeout,
        send_timeout = send_timeout,
        read_timeout = read_timeout,
        keepalive_timeout = keepalive_timeout,
        keepalive_cons = pool_size,
        max_redirection = max_redirections,
        max_connection_attempts = max_connection_attempts,
        max_connection_timeout = max_connection_timeout,
        auth = auth,
        connect_opts = {
          ssl = ssl,
          ssl_verify = ssl_verify,
          server_name = server_name,
          pool = pool,
          pool_size = pool_size,
          backlog = backlog,
        },
      },
    }, metatable)
  end

  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    options = {
      name = name,
      dict_name = lock_zone,
      refresh_lock_key = lock_prefix,
      serv_list = nodes,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      keepalive_cons = pool_size,
      max_redirection = max_redirections,
      max_connection_attempts = max_connection_attempts,
      max_connection_timeout = max_connection_timeout,
      auth = auth,
    },
  }, metatable)
end


return storage
