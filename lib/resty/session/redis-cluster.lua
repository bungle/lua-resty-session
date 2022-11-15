local redis = require "resty.rediscluster"


local setmetatable = setmetatable
local null = ngx.null


local function exec(self, func, ...)
  local red = redis:new(self.options)

  local ok, err = func(red, ...)
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


function metatable:set(key, value, ttl)
  return exec(self, redis.set, key, value, "EX", ttl)
end


function metatable:get(key)
  return exec(self, redis.get, key)
end


function metatable:ttl(key)
  return exec(self, redis.ttl, key)
end


function metatable:expire(key, ttl)
  return exec(self, redis.expire, key, ttl)
end


function metatable:delete(key)
  return exec(self, redis.del, key)
end


local storage = {}


function storage.new(configuration)
  local name                    = configuration and configuration.name                    --or DEFAULT_NAME
  local dict_name               = configuration and configuration.dict_name               --or DEFAULT_DICT_NAME
  local refresh_lock_key        = configuration and configuration.refresh_lock_key        --or DEFAULT_REFRESH_LOCK_KEY
  local serv_list               = configuration and configuration.serv_list               --or DEFAULT_SERV_LIST
  local auth                    = configuration and configuration.auth                    --or DEFAULT_AUTH
  local prefix                  = configuration and configuration.prefix                  --or DEFAULT_PREFIX
  local connect_timeout         = configuration and configuration.connect_timeout         --or DEFAULT_CONNECT_TIMEOUT
  local send_timeout            = configuration and configuration.send_timeout            --or DEFAULT_SEND_TIMEOUT
  local read_timeout            = configuration and configuration.read_timeout            --or DEFAULT_READ_TIMEOUT
  local keepalive_timeout       = configuration and configuration.keepalive_timeout       --or DEFAULT_KEEPALIVE_TIMEOUT
  local keepalive_cons          = configuration and configuration.keepalive_cons          --or DEFAULT_KEEPALIVE_CONS
  local max_redirection         = configuration and configuration.max_redirection         --or DEFAULT_MAX_REDIRECTION
  local max_connection_attempts = configuration and configuration.max_connection_attempts --or DEFAULT_MAX_CONNECTION_ATTEMPTS
  local max_connection_timeout  = configuration and configuration.max_connection_timeout  --or DEFAULT_MAX_CONNECTION_TIMEOUT
  local pool                    = configuration and configuration.pool                    --or DEFAULT_POOL
  local pool_size               = configuration and configuration.pool_size               --or DEFAULT_POOL_SIZE
  local backlog                 = configuration and configuration.backlog                 --or DEFAULT_BACKLOG
  local ssl                     = configuration and configuration.ssl                     --or DEFAULT_SSL
  local ssl_verify              = configuration and configuration.ssl_verify              --or DEFAULT_SSL_VERIFY
  local server_name             = configuration and configuration.server_name             --or DEFAULT_SERVER_NAME

  -- TODO: enable_slave_read?

  if ssl ~= nil or ssl_verify ~= nil or server_name or pool or pool_size or backlog then
    return setmetatable({
      prefix = prefix,
      options = {
        name = name,
        dict_name = dict_name,
        refresh_lock_key = refresh_lock_key,
        serv_list = serv_list,
        connect_timeout = connect_timeout,
        send_timeout = send_timeout,
        read_timeout = read_timeout,
        keepalive_timeout = keepalive_timeout,
        keepalive_cons = keepalive_cons,
        max_redirection = max_redirection,
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
    options = {
      name = name,
      dict_name = dict_name,
      refresh_lock_key = refresh_lock_key,
      serv_list = serv_list,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      keepalive_cons = keepalive_cons,
      max_redirection = max_redirection,
      max_connection_attempts = max_connection_attempts,
      max_connection_timeout = max_connection_timeout,
      auth = auth,
    },
  }, metatable)
end


return storage
