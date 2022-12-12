local redis = require "resty.rediscluster"
local get_name = require "resty.session.utils".get_name


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = redis.set
local GET = redis.get
local TTL = redis.ttl
local EXPIRE = redis.expire
local UNLINK = redis.unlink


local function exec(self, func, name, key, ...)
  local red = redis:new(self.options)

  local ok, err = func(red, get_name(self, name, key), ...)
  if err then
    return nil, err
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
  return exec(self, SET, name, key, value, "EX", ttl)
end


function metatable:get(name, key)
  return exec(self, GET, name, key)
end


function metatable:ttl(name, key)
  return exec(self, TTL, name, key)
end


function metatable:expire(name, key, ttl)
  return exec(self, EXPIRE, name, key, ttl)
end


function metatable:delete(name, key)
  return exec(self, UNLINK, name, key)
end


local storage = {}


function storage.new(configuration)
  local prefix                  = configuration and configuration.prefix
  local suffix                  = configuration and configuration.suffix

  local name                    = configuration and configuration.name
  local lock_zone               = configuration and configuration.lock_zone
  local lock_prefix             = configuration and configuration.lock_prefix
  local nodes                   = configuration and configuration.nodes
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
