local memcached    = require "resty.memcached"


local setmetatable = setmetatable
local shared = ngx.shared
local assert = assert
local error = error


local DEFAULT_HOST   = "127.0.0.1"
local DEFAULT_PORT   = 11211
local DEFAULT_SOCKET


local function exec(self, func, ...)
  local memcached = self.memcached
  local ok, err do
    local socket = self.socket
    if socket then
      ok, err = memcached:connect(socket)
    else
      ok, err = memcached:connect(self.host, self.port)
    end
  end
  if not ok then
    return nil, err
  end

  local a, b, c = func(memcached, ...)

  memcached:set_keepalive(self.idle_timeout)

  return a, b, c
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl)
  local ok, err = exec(self, self.memcached.set, key, value, ttl)
  if not ok then
    return nil, err
  end

  return true
end


function metatable:get(key)
  local value, _, err = exec(self, self.memcached.get, key)
  if not value then
    return nil, err
  end

  return true
end


function metatable:expire(key, ttl)
  local ok, err = exec(self, self.memcached.touch, key, ttl)
  if not ok then
    return nil, err
  end

  return true
end


function metatable:delete(key)
  local ok, err = exec(self, self.memcached.delete, key)
  if not ok then
    return nil, err
  end

  return true
end


local storage = {}


function storage.new(configuration)
  local host            = configuration and configuration.host            or DEFAULT_HOST
  local port            = configuration and configuration.port            or DEFAULT_PORT
  local socket          = configuration and configuration.socket          or DEFAULT_SOCKET
  local prefix          = configuration and configuration.prefix          or DEFAULT_PREFIX
  local connect_timeout = configuration and configuration.connect_timeout or DEFAULT_CONNECT_TIMEOUT
  local send_timeout    = configuration and configuration.send_timeout    or DEFAULT_SEND_TIMEOUT
  local read_timeout    = configuration and configuration.read_timeout    or DEFAULT_READ_TIMEOUT
  local idle_timeout    = configuration and configuration.idle_timeout    or DEFAULT_IDLE_TIMEOUT
  local pool            = configuration and configuration.pool            or DEFAULT_POOL
  local pool_size       = configuration and configuration.pool_size       or DEFAULT_POOL_SIZE
  local backlog         = configuration and configuration.backlog         or DEFAULT_BACKLOG
  local ssl             = configuration and configuration.ssl             or DEFAULT_SSL
  local ssl_verify      = configuration and configuration.ssl_verify      or DEFAULT_SSL_VERIFY
  local ssl_server_name = configuration and configuration.ssl_server_name or DEFAULT_SSL_SERVER_NAME

  local memcached = memcached:new()

  memcached:set_timeouts(connect_timeout, send_timeout, read_timeout)

  return setmetatable({
    memcached = memcached,
  }, metatable)
end


return storage
