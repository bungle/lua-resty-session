local memcached = require "resty.memcached"


local setmetatable = setmetatable
local null = ngx.null


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 11211
local DEFAULT_SOCKET


local function exec(self, func, ...)
  local memc = memcached:new()

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    memc:set_timeouts(connect_timeout, send_timeout, read_timeout)
  end

  self.memcached = memc

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

  if self.ssl and memc:getreusedtimes() == 0 then
    ok, err = memc:sslhandshake(false, self.server_name, self.ssl_verify)
    if not ok then
      memc:close()
      return nil, err
    end
  end

  if func == memc.get then
    local _
    ok, _, err = memc:get(...)
  else
    ok, err = func(memc, ...)
  end

  if err then
    memc:close()
    return nil, err
  end

  if not memc:set_keepalive(self.idle_timeout) then
    memc:close()
  end

  if ok == null then
    ok = nil
  end

  return ok, err
end


local metatable = {}


metatable.__index = metatable


function metatable:set(key, value, ttl)
  return exec(self, memcached.set, key, value, ttl)
end


function metatable:get(key)
  return exec(self, memcached.get, key)
end


function metatable:expire(key, ttl)
  return exec(self, memcached.touch, key, ttl)
end


function metatable:delete(key)
  return exec(self, memcached.delete, key)
end


local storage = {}


function storage.new(configuration)
  local host            = configuration and configuration.host            or DEFAULT_HOST
  local port            = configuration and configuration.port            or DEFAULT_PORT
  local socket          = configuration and configuration.socket          or DEFAULT_SOCKET
  local prefix          = configuration and configuration.prefix          --or DEFAULT_PREFIX
  local connect_timeout = configuration and configuration.connect_timeout --or DEFAULT_CONNECT_TIMEOUT
  local send_timeout    = configuration and configuration.send_timeout    --or DEFAULT_SEND_TIMEOUT
  local read_timeout    = configuration and configuration.read_timeout    --or DEFAULT_READ_TIMEOUT
  local idle_timeout    = configuration and configuration.idle_timeout    --or DEFAULT_IDLE_TIMEOUT
  local pool            = configuration and configuration.pool            --or DEFAULT_POOL
  local pool_size       = configuration and configuration.pool_size       --or DEFAULT_POOL_SIZE
  local backlog         = configuration and configuration.backlog         --or DEFAULT_BACKLOG
  local ssl             = configuration and configuration.ssl             --or DEFAULT_SSL
  local ssl_verify      = configuration and configuration.ssl_verify      --or DEFAULT_SSL_VERIFY
  local server_name     = configuration and configuration.server_name     --or DEFAULT_SERVER_NAME

  local options
  if pool or pool_size or backlog then
    options = {
      pool = pool,
      pool_size = pool_size,
      backlog = backlog,
    }
  end

  return setmetatable({
    host = host,
    port = port,
    socket = socket,
    prefix = prefix,
    connect_timeout = connect_timeout,
    send_timeout = send_timeout,
    read_timeout = read_timeout,
    idle_timeout = idle_timeout,
    options = options,
    ssl = ssl,
    ssl_verify = ssl_verify,
    server_name = server_name,
  }, metatable)
end


return storage
