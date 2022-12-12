local memcached = require "resty.memcached"
local get_name = require "resty.session.utils".get_name


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = memcached.set
local GET = memcached.get
local TOUCH = memcached.touch
local DELETE = memcached.delete


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 11211


local function exec(self, func, name, key, ...)
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

  key = get_name(self, name, key)

  if func == memc.get then
    local _
    ok, _, err = memc:get(key)
  else
    ok, err = func(memc, key, ...)
  end

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


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(name, key, value, ttl)
  return exec(self, SET, name, key, value, ttl)
end


function metatable:get(name, key)
  return exec(self, GET, name, key)
end


function metatable:expire(name, key, ttl)
  return exec(self, TOUCH, name, key, ttl)
end


function metatable:delete(name, key)
  return exec(self, DELETE, name, key)
end


local storage = {}


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
