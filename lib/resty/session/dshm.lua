local dshm = require "resty.dshm"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = dshm.set
local GET = dshm.get
local TOUCH = dshm.touch
local DELETE = dshm.delete


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 4321


local function get_name(self, key)
  local prefix = self.prefix
  local suffix = self.suffix
  if prefix and suffix then
    return prefix .. key .. suffix
  elseif prefix then
    return prefix .. key
  elseif suffix then
    return key .. suffix
  else
    return key
  end
end


local function exec(self, func, key, ...)
  local dshmc = dshm:new()

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    dshmc.sock:set_timeouts(connect_timeout, send_timeout, read_timeout)
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

  ok, err = func(dshmc, get_name(self, key), ...)
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


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl)
  return exec(self, SET, key, value, ttl)
end


function metatable:get(key)
  return exec(self, GET, key)
end


function metatable:expire(key, ttl)
  return exec(self, TOUCH, key, ttl)
end


function metatable:delete(key)
  return exec(self, DELETE, key)
end


local storage = {}


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
