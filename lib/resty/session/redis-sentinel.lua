local redis = require "resty.redis.connector"


local setmetatable = setmetatable
local error = error
local null = ngx.null


local SET = "set"
local GET = "get"
local TTL = "ttl"
local EXPIRE = "expire"
local UNLINK = "unlink"


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
  local red, err = self.connector:connect()
  if not red then
    return nil, err
  end

  local ok, err = red[func](red, get_name(self, key), ...)
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
  local prefix            = configuration and configuration.prefix
  local suffix            = configuration and configuration.suffix

  local master            = configuration and configuration.master
  local role              = configuration and configuration.role
  local sentinels         = configuration and configuration.sentinels
  local sentinel_username = configuration and configuration.sentinel_username
  local sentinel_password = configuration and configuration.sentinel_password

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
      db = database,
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
      db = database,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      keepalive_poolsize = pool_size,
    })
  end

  return setmetatable({
    prefix = prefix,
    suffix = suffix,
    connector = connector,
  }, metatable)
end


return storage
