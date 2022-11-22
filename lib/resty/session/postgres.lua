--[[
CREATE TABLE IF NOT EXISTS sessions (
  sid  CHAR(43) PRIMARY KEY,
  data TEXT,
  ttl  TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ON sessions (ttl);
]]

local pgmoon = require "pgmoon"


local setmetatable = setmetatable
local error = error
local fmt = string.format


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 5432


local SET = "INSERT INTO %s (sid, data, ttl) VALUES ('%s', '%s', TO_TIMESTAMP(%d) AT TIME ZONE 'UTC') ON CONFLICT (sid) DO UPDATE SET data = EXCLUDED.data"
local GET = "SELECT data FROM %s WHERE sid = '%s' AND ttl >= TO_TIMESTAMP(%d) AT TIME ZONE 'UTC'"
local EXPIRE = "UPDATE %s SET ttl = TO_TIMESTAMP(%d) AT TIME ZONE 'UTC' WHERE sid = '%s' AND ttl > TO_TIMESTAMP(%d) AT TIME ZONE 'UTC'"
local DELETE = "DELETE FROM %s WHERE sid = '%s'"


local function exec(self, query)
  local pg = pgmoon.new(self.options)

  local connect_timeout = self.connect_timeout
  local send_timeout = self.send_timeout
  local read_timeout = self.read_timeout
  if connect_timeout or send_timeout or read_timeout then
    if pg.sock and pg.sock.settimeouts then
      pg.sock:settimeouts(connect_timeout, send_timeout, read_timeout)
    else
      pg:settimeout(connect_timeout)
    end
  end

  local ok, err = pg:connect()
  if not ok then
    return nil, err
  end

  local schema = self.schema
  if schema then
    ok, err = pg:query("SET SCHEMA " .. pg:escape_literal(schema))
    if not ok then
      return nil, err
    end
  end

  ok, err = pg:query(query)

  if not pg:keepalive(self.keepalive_timeout) then
    pg:close()
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
    return nil
  end
  local data = row.data
  if not row.data then
    return nil
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

  local application       = configuration and configuration.application
  local username          = configuration and configuration.username
  local password          = configuration and configuration.password
  local database          = configuration and configuration.database
  local schema            = configuration and configuration.schema
  local table_name        = configuration and configuration.table

  local connect_timeout   = configuration and configuration.connect_timeout
  local send_timeout      = configuration and configuration.send_timeout
  local read_timeout      = configuration and configuration.read_timeout
  local keepalive_timeout = configuration and configuration.keepalive_timeout

  local pool              = configuration and configuration.pool
  local pool_size         = configuration and configuration.pool_size
  local backlog           = configuration and configuration.backlog
  local ssl               = configuration and configuration.ssl
  local ssl_verify        = configuration and configuration.ssl_verify
  local ssl_required      = configuration and configuration.ssl_required

  return setmetatable({
    schema = schema,
    table = table_name,
    connect_timeout = connect_timeout,
    send_timeout = send_timeout,
    read_timeout = read_timeout,
    keepalive_timeout = keepalive_timeout,
    options = {
      host = host,
      port = port,
      application_name = application,
      user = username,
      password = password,
      database = database,
      socket_type = "nginx",
      pool = pool,
      pool_size = pool_size,
      backlog = backlog,
      ssl = ssl,
      ssl_verify = ssl_verify,
      ssl_required = ssl_required,
    }
  }, metatable)
end


return storage
