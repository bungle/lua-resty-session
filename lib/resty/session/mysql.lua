--[[
CREATE TABLE IF NOT EXISTS sessions (
  sid  CHAR(43) PRIMARY KEY,
  data LONGTEXT,
  ttl  DATETIME,
  INDEX (ttl)
) CHARACTER SET ascii;
]]

local mysql = require "resty.mysql"


local setmetatable = setmetatable
local error = error
local fmt = string.format


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 3306


local SET = "INSERT INTO %s (sid, data, ttl) VALUES ('%s', '%s', FROM_UNIXTIME(%d))"
local GET = "SELECT data FROM %s WHERE sid = '%s' AND ttl >= FROM_UNIXTIME(%d)"
local EXPIRE = "UPDATE %s SET ttl = FROM_UNIXTIME(%d) WHERE sid = '%s' AND ttl > FROM_UNIXTIME(%d)"
local DELETE = "DELETE FROM %s WHERE sid = '%s'"


local function exec(self, query)
  local my = mysql:new()

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    if my.sock and my.sock.settimeouts then
      my.sock:settimeouts(connect_timeout, send_timeout, read_timeout)
    else
      my:set_timeout(connect_timeout)
    end
  end

  local ok, err = my:connect(self.options)
  if not ok then
    return nil, err
  end

  ok, err = my:query(query)

  if not my:set_keepalive(self.keepalive_timeout) then
    my:close()
  end

  return ok, err
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value, ttl, current_time)
  return exec(self, fmt(SET, self.table, key, value, ttl + current_time))
end


function metatable:get(key, current_time)
  local res, err = exec(self, fmt(GET, self.table, key, current_time))
  if not res then
    return nil, err
  end
  local row = res[1]
  if not row then
    return nil, "session not found"
  end
  local data = row.data
  if not row.data then
    return nil, "session not found"
  end
  return data
end


function metatable:expire(key, ttl, current_time)
  ttl = ttl + current_time
  return exec(self, fmt(EXPIRE, self.table, ttl, key, ttl))
end


function metatable:delete(key)
  return exec(self, fmt(DELETE, self.table, key))
end


local storage = {}


function storage.new(configuration)
  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT
  local socket            = configuration and configuration.socket

  local username          = configuration and configuration.username
  local password          = configuration and configuration.password
  local charset           = configuration and configuration.charset
  local database          = configuration and configuration.database
  local table_name        = configuration and configuration.table
  local max_packet_size   = configuration and configuration.max_packet_size

  local connect_timeout   = configuration and configuration.connect_timeout
  local send_timeout      = configuration and configuration.send_timeout
  local read_timeout      = configuration and configuration.read_timeout
  local keepalive_timeout = configuration and configuration.keepalive_timeout

  local pool              = configuration and configuration.pool
  local pool_size         = configuration and configuration.pool_size
  local backlog           = configuration and configuration.backlog
  local ssl               = configuration and configuration.ssl
  local ssl_verify        = configuration and configuration.ssl_verify

  if socket then
    return setmetatable({
      table = table_name,
      connect_timeout = connect_timeout,
      send_timeout = send_timeout,
      read_timeout = read_timeout,
      keepalive_timeout = keepalive_timeout,
      options = {
        path = socket,
        user = username,
        password = password,
        charset = charset,
        database = database,
        max_packet_size = max_packet_size,
        pool = pool,
        pool_size = pool_size,
        backlog = backlog,
        ssl = ssl,
        ssl_verify = ssl_verify,
      }
    }, metatable)
  end

  return setmetatable({
    table = table_name,
    connect_timeout = connect_timeout,
    send_timeout = send_timeout,
    read_timeout = read_timeout,
    keepalive_timeout = keepalive_timeout,
    options = {
      host = host,
      port = port,
      user = username,
      password = password,
      charset = charset,
      database = database,
      max_packet_size = max_packet_size,
      pool = pool,
      pool_size = pool_size,
      backlog = backlog,
      ssl = ssl,
      ssl_verify = ssl_verify,
    }
  }, metatable)
end


return storage
