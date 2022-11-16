local redis = require "resty.redis.connector"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = "set"
local GET = "get"
local TTL = "ttl"
local EXPIRE = "expire"
local UNLINK = "unlink"


local function exec(self, func, ...)
  local red, err = self.connector:connect()
  if not red then
    return nil, err
  end

  local ok, err = red[func](red, ...)
  if err then
    return nil, err
  end

  if ok == null then
    ok = nil
  end

  self.connector:set_keepalive(red)

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

  local master                  = configuration and configuration.master                  --or DEFAULT_MASTER
  local role                    = configuration and configuration.role                    --or DEFAULT_ROLE
  local sentinels               = configuration and configuration.sentinels               --or DEFAULT_SENTINELS
  local sentinel_username       = configuration and configuration.sentinel_username       --or DEFAULT_SENTINEL_USERNAME
  local sentinel_password       = configuration and configuration.sentinel_password       --or DEFAULT_SENTINEL_PASSWORD

  local username                = configuration and configuration.username                --or DEFAULT_USERNAME
  local password                = configuration and configuration.password                --or DEFAULT_PASSWORD
  local db                      = configuration and configuration.db                      --or DEFAULT_DB

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

  local connector
  if ssl ~= nil or ssl_verify ~= nil or server_name or pool or pool_size or backlog then
    connector = redis.new({
      master_name = master,
      role = role,
      sentinels = sentinels,
      sentinel_username = sentinel_username,
      sentinel_password = sentinel_password,
      username = username,
      password = password,
      db = db,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      keepalive_poolsize = pool_size,
      connection_options = {
        ssl = ssl,
        ssl_verify = ssl_verify,
        server_name = server_name,
        pool = pool,
        pool_size = pool_size,
        backlog = backlog,
      }
    })
  else
    connector = redis.new({
      master_name = master,
      role = role,
      sentinels = sentinels,
      sentinel_username = sentinel_username,
      sentinel_password = sentinel_password,
      username = username,
      password = password,
      db = db,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      keepalive_poolsize = pool_size,
    })
  end

  return setmetatable({
    prefix = prefix,
    connector = connector,
  }, metatable)
end


return storage
