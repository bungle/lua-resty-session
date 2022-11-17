local redis = require "resty.rediscluster"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = redis.set
local GET = redis.get
local TTL = redis.ttl
local EXPIRE = redis.expire
local UNLINK = redis.unlink


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
  local red = redis:new(self.options)

  local ok, err = func(red, get_name(self, key), ...)
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
  local prefix                  = configuration and configuration.prefix                  --or DEFAULT_PREFIX
  local suffix                  = configuration and configuration.suffix                  --or DEFAULT_SUFFIX

  local name                    = configuration and configuration.name                    --or DEFAULT_NAME
  local lock_zone               = configuration and configuration.lock_zone               --or DEFAULT_LOCK_ZONE
  local lock_prefix             = configuration and configuration.lock_prefix             --or DEFAULT_LOCK_PREFIX
  local nodes                   = configuration and configuration.nodes                   --or DEFAULT_NODES
  local max_redirections        = configuration and configuration.max_redirections        --or DEFAULT_MAX_REDIRECTIONS
  local max_connection_attempts = configuration and configuration.max_connection_attempts --or DEFAULT_MAX_CONNECTION_ATTEMPTS
  local max_connection_timeout  = configuration and configuration.max_connection_timeout  --or DEFAULT_MAX_CONNECTION_TIMEOUT

  local username                = configuration and configuration.username                --or DEFAULT_USERNAME
  local password                = configuration and configuration.password                --or DEFAULT_PASSWORD

  local connect_timeout         = configuration and configuration.connect_timeout         --or DEFAULT_CONNECT_TIMEOUT
  local send_timeout            = configuration and configuration.send_timeout            --or DEFAULT_SEND_TIMEOUT
  local read_timeout            = configuration and configuration.read_timeout            --or DEFAULT_READ_TIMEOUT
  local keepalive_timeout       = configuration and configuration.keepalive_timeout       --or DEFAULT_KEEPALIVE_TIMEOUT

  local pool                    = configuration and configuration.pool                    --or DEFAULT_POOL
  local pool_size               = configuration and configuration.pool_size               --or DEFAULT_POOL_SIZE
  local backlog                 = configuration and configuration.backlog                 --or DEFAULT_BACKLOG
  local ssl                     = configuration and configuration.ssl                     --or DEFAULT_SSL
  local ssl_verify              = configuration and configuration.ssl_verify              --or DEFAULT_SSL_VERIFY
  local server_name             = configuration and configuration.server_name             --or DEFAULT_SERVER_NAME

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
