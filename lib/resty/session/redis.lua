local redis = require "resty.redis"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = redis.set
local GET = redis.get
local TTL = redis.ttl
local EXPIRE = redis.expire
local UNLINK = redis.unlink


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 6379


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

  ok, err = func(red, get_name(self, key), ...)
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


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl)
  return exec(self, SET, key, value, "EX", ttl)
end


function metatable:get(key)
  return exec(self, GET, key)
end


function metatable:ttl(key)
  return exec(self, TTL, key)
end


function metatable:expire(key, ttl)
  return exec(self, EXPIRE, key, ttl)
end


function metatable:delete(key)
  return exec(self, UNLINK, key)
end


local storage = {}


function storage.new(configuration)
  local prefix            = configuration and configuration.prefix            --or DEFAULT_PREFIX
  local suffix            = configuration and configuration.suffix            --or DEFAULT_SUFFIX

  local host              = configuration and configuration.host              or DEFAULT_HOST
  local port              = configuration and configuration.port              or DEFAULT_PORT
  local socket            = configuration and configuration.socket            --or DEFAULT_SOCKET

  local username          = configuration and configuration.username          --or DEFAULT_USERNAME
  local password          = configuration and configuration.password          --or DEFAULT_PASSWORD
  local database          = configuration and configuration.database          --or DEFAULT_DATABASE

  local connect_timeout   = configuration and configuration.connect_timeout   --or DEFAULT_CONNECT_TIMEOUT
  local send_timeout      = configuration and configuration.send_timeout      --or DEFAULT_SEND_TIMEOUT
  local read_timeout      = configuration and configuration.read_timeout      --or DEFAULT_READ_TIMEOUT
  local keepalive_timeout = configuration and configuration.keepalive_timeout --or DEFAULT_KEEPALIVE_TIMEOUT

  local pool              = configuration and configuration.pool              --or DEFAULT_POOL
  local pool_size         = configuration and configuration.pool_size         --or DEFAULT_POOL_SIZE
  local backlog           = configuration and configuration.backlog           --or DEFAULT_BACKLOG
  local ssl               = configuration and configuration.ssl               --or DEFAULT_SSL
  local ssl_verify        = configuration and configuration.ssl_verify        --or DEFAULT_SSL_VERIFY
  local server_name       = configuration and configuration.server_name       --or DEFAULT_SERVER_NAME

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