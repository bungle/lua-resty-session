---
-- Redis backend for session library
--
-- @module resty.session.redis


local redis = require "resty.redis"
local get_name = require "resty.session.utils".get_name


local setmetatable = setmetatable
local error = error
local time = ngx.time
local null = ngx.null


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 6379


local function SET(self, red, name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  if not metadata and not old_key then
    return red:set(get_name(self, name, key), value, "EX", ttl)
  end

  local old_name
  local old_ttl
  if old_key then
    old_name = get_name(self, name, old_key)
    if not remember then
      -- redis < 7.0
      old_ttl = red:ttl(old_name)
    end
  end

  red:init_pipeline()
  red:set(get_name(self, name, key), value, "EX", ttl)

  -- redis < 7.0
  if old_name then
    if remember then
      red:unlink(old_name)
    elseif not old_ttl or old_ttl > stale_ttl then
      red:expire(old_name, stale_ttl)
    end
  end

  -- redis >= 7.0
  --if old_key then
  --  if remember then
  --    red:unlink(get_name(self, name, old_key))
  --  else
  --    red:expire(get_name(self, name, old_key), stale_ttl, "LT")
  --  end
  --end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    local score = current_time - 1
    local new_score = current_time + ttl
    for i = 1, #audiences do
      local k = get_name(self, name, audiences[i], subjects[i])
      red:zremrangebyscore(k, 0, score)
      red:zadd(k, new_score, key)
      if old_key then
        red:zrem(k, old_key) -- TODO: remove or set new score?
      end
      red:expire(k, ttl)
    end
  end

  return red:commit_pipeline()
end


local function GET(self, red, name, key)
  return red:get(get_name(self, name, key))
end


local function UNLINK(self, red, name, key, metadata)
  if not metadata then
    return red:unlink(get_name(self, name, key))
  end

  red:init_pipeline()
  red:unlink(get_name(self, name, key))
  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  local score = time() - 1
  for i = 1, #audiences do
    local k = get_name(self, name, audiences[i], subjects[i])
    red:zremrangebyscore(k, 0, score)
    red:zrem(k, key)
  end
  return red:commit_pipeline()
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
    if socket then
      ok, err = red:connect(socket, self.options)
    else
      ok, err = red:connect(self.host, self.port, self.options)
    end
  end
  if not ok then
    return nil, err
  end

  if red:getreusedtimes() == 0 then
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
  end

  local database = self.database
  if database then
    ok, err = red:select(database)
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


function metatable:delete(...)
  return exec(self, UNLINK, ...)
end


local storage = {}


---
-- Configuration
-- @section configuration


---
-- Redis storage backend configuration
-- @field prefix prefix for the keys stored in redis
-- @field suffix suffix for the keys stored in redis
-- @field host the host to connect (defaults to `"127.0.0.1"`)
-- @field port the port to connect (defaults to `6379`)
-- @field socket the socket file to connect to (defaults to `nil`)
-- @field username the database username to authenticate
-- @field password password for authentication
-- @field database the database to connect
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
-- Create a Redis storage.
--
-- This creates a new Redis storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  redis storage @{configuration}
-- @treturn      table                  redis storage instance
function storage.new(configuration)
  local prefix            = configuration and configuration.prefix
  local suffix            = configuration and configuration.suffix

  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT
  local socket            = configuration and configuration.socket

  local username          = configuration and configuration.username
  local password          = configuration and configuration.password
  local database          = configuration and configuration.database

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
      }
    })
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
  }, metatable)
end


return storage
