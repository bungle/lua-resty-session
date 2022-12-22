---
-- Postgres backend for session library
-- @module resty.session.postgres


--[[
-- create a table for session data:

CREATE TABLE IF NOT EXISTS sessions (
  sid  CHAR(43) PRIMARY KEY,
  name TEXT,
  data TEXT,
  ttl  TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ON sessions (ttl);

-- when collecting information about subjects, also create:

CREATE TABLE IF NOT EXISTS sessions_meta (
  aud TEXT,
  sub TEXT,
  sid CHAR(43) REFERENCES sessions (sid) ON DELETE CASCADE ON UPDATE CASCADE,
  PRIMARY KEY (aud, sub, sid)
);
CREATE INDEX ON sessions_meta (ttl);
]]


local buffer = require "string.buffer"
local pgmoon = require "pgmoon"


local setmetatable = setmetatable
local error = error
local fmt = string.format


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 5432


local SET = "INSERT INTO %s (sid, name, data, ttl) VALUES ('%s', '%s', '%s', TO_TIMESTAMP(%d) AT TIME ZONE 'UTC') ON CONFLICT (sid) DO UPDATE SET data = EXCLUDED.data, ttl = EXCLUDED.ttl"
local SET_META_PREFIX = "INSERT INTO %s (aud, sub, sid) VALUES "
local SET_META_VALUES = "('%s', '%s', '%s')"
local SET_META_SUFFIX = " ON CONFLICT DO NOTHING"
local GET = "SELECT data FROM %s WHERE sid = '%s' AND ttl >= TO_TIMESTAMP(%d) AT TIME ZONE 'UTC'"
local EXPIRE = "UPDATE %s SET ttl = TO_TIMESTAMP(%d) AT TIME ZONE 'UTC' WHERE sid = '%s' AND ttl > TO_TIMESTAMP(%d) AT TIME ZONE 'UTC'"
local DELETE = "DELETE FROM %s WHERE sid = '%s'"


local SQL = buffer.new()
local STM_DELIM = ";\n"
local VAL_DELIM = ", "


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


function metatable:set(name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  local table = self.table
  local exp = ttl + current_time

  if not metadata and not old_key then
    return exec(self, fmt(SET, table, key, name, value, exp))
  end

  SQL:reset():putf(SET, table, key, name, value, exp)

  if old_key then
    if remember then
      SQL:put(STM_DELIM):putf(DELETE, table, old_key)
    else
      local stale_exp = stale_ttl + current_time
      SQL:put(STM_DELIM):putf(EXPIRE, table, stale_exp, old_key, stale_exp)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    local count = #audiences

    SQL:put(STM_DELIM):putf(SET_META_PREFIX, table .. "_meta")

    for i = 1, count do
      if i > 1 then
        SQL:put(VAL_DELIM)
      end
      SQL:putf(SET_META_VALUES, audiences[i], subjects[i], key, exp)
    end

    SQL:putf(SET_META_SUFFIX)
  end

  return exec(self, SQL:tostring())
end


function metatable:get(_, key, current_time)
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


function metatable:delete(_, key)
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
  local table_name        = configuration and configuration.table
  local table_name_meta   = configuration and configuration.table_meta

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
    table = table_name,
    table_meta = table_name_meta or (table_name .. "_meta"), -- TODO: better name for table that is collection
                                                             --       information about audiences and subjects
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
