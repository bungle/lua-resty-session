---
-- MySQL / MariaDB backend for session library
--
-- @module resty.session.mysql


---
-- Database
-- @section database


---
-- Sessions table.
--
-- Database table that stores session data.
--
-- @usage
-- CREATE TABLE IF NOT EXISTS sessions (
--   sid  CHAR(43) PRIMARY KEY,
--   name TINYTEXT,
--   data LONGTEXT,
--   exp  DATETIME,
--   INDEX (exp)
-- ) CHARACTER SET ascii;
-- @table sessions


---
-- Sessions metadata table.
--
-- This is only needed if you want to store session metadata.
--
-- @usage
-- CREATE TABLE IF NOT EXISTS sessions_meta (
--   aud TINYTEXT,
--   sub TINYTEXT,
--   sid CHAR(43),
--   exp DATETIME,
--   PRIMARY KEY (aud, sub, sid),
--   CONSTRAINT  FOREIGN KEY (sid) REFERENCES sessions(sid) ON DELETE CASCADE ON UPDATE CASCADE
-- ) CHARACTER SET ascii;
-- @table metadata


local buffer = require "string.buffer"
local mysql = require "resty.mysql"


local setmetatable = setmetatable
local error = error
local fmt = string.format
local random = math.random


local DEFAULT_HOST = "127.0.0.1"
local DEFAULT_PORT = 3306
local DEFAULT_TABLE = "sessions"
local DEFAULT_CHARSET = "ascii"


local SET = "INSERT INTO %s (sid, name, data, exp) VALUES ('%s', '%s', '%s', FROM_UNIXTIME(%d)) AS new ON DUPLICATE KEY UPDATE data = new.data"
local SET_META_PREFIX = "INSERT INTO %s (aud, sub, sid, exp) VALUES "
local SET_META_VALUES = "('%s', '%s', '%s', FROM_UNIXTIME(%d))"
local SET_META_SUFFIX = " ON DUPLICATE KEY UPDATE exp = FROM_UNIXTIME(%d)"
local GET_META = "SELECT sid, exp FROM %s WHERE aud = '%s' AND sub = '%s' AND exp >= FROM_UNIXTIME(%d)"
local GET = "SELECT data FROM %s WHERE sid = '%s' AND exp >= FROM_UNIXTIME(%d)"
local EXPIRE = "UPDATE %s SET exp = FROM_UNIXTIME(%d) WHERE sid = '%s' AND exp > FROM_UNIXTIME(%d)"
local DELETE = "DELETE FROM %s WHERE sid = '%s'"
local CLEANUP = "DELETE FROM %s WHERE exp < FROM_UNIXTIME(%d)"


local SQL = buffer.new()
local STM_DELIM = ";\n"
local VAL_DELIM = ", "
-- 1/1000
local CLEANUP_PROBABILITY = 0.001


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


---
-- Storage
-- @section instance


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


---
-- Store session data.
--
-- @function instance:set
-- @tparam  string   name  cookie name
-- @tparam  string   key   session key
-- @tparam  string   value session value
-- @tparam  number   ttl   session ttl
-- @tparam  number   current_time  current time
-- @tparam  string   old_key  old session id
-- @tparam  string   stale_ttl  stale ttl
-- @tparam  table    metadata  table of metadata
-- @tparam  table    remember  whether storing persistent session or not
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:set(name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  local cleanup = random() < CLEANUP_PROBABILITY
  local table = self.table
  local exp = ttl + current_time

  if not metadata and not old_key then
    return exec(self, fmt(SET, table, key, name, value, exp))
  end

  SQL:reset():putf(SET, table, key, name, value, exp)

  local table_meta = self.table_meta
  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    local count = #audiences

    SQL:put(STM_DELIM):putf(SET_META_PREFIX, table_meta)

    for i = 1, count do
      if i > 1 then
        SQL:put(VAL_DELIM)
      end
      SQL:putf(SET_META_VALUES, audiences[i], subjects[i], key, exp)
    end

    SQL:putf(SET_META_SUFFIX, exp)

    if old_key then
      local stale_exp = stale_ttl + current_time
      SQL:put(STM_DELIM):putf(SET_META_PREFIX, table_meta)

      for i = 1, count do
        if i > 1 then
          SQL:put(VAL_DELIM)
        end
        SQL:putf(SET_META_VALUES, audiences[i], subjects[i], old_key, stale_exp)
      end

      SQL:putf(SET_META_SUFFIX, stale_exp)
    end

    if cleanup then
      SQL:put(STM_DELIM):putf(CLEANUP, self.table_meta, current_time)
    end
  end

  if old_key then
    if remember then
      SQL:put(STM_DELIM):putf(DELETE, table, old_key)
    else
      local stale_exp = stale_ttl + current_time
      SQL:put(STM_DELIM):putf(EXPIRE, table, stale_exp, old_key, stale_exp)
    end
  end

  if cleanup then
    SQL:put(STM_DELIM):putf(CLEANUP, self.table, current_time)
  end

  return exec(self, SQL:tostring())
end


---
-- Retrieve session data.
--
-- @function instance:get
-- @tparam  string     name cookie name
-- @tparam  string     key  session key
-- @treturn string|nil      session data
-- @treturn string          error message
function metatable:get(name, key, current_time)
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


---
-- Delete session data.
--
-- @function instance:delete
-- @tparam  string      name cookie name
-- @tparam  string      key  session key
-- @tparam[opt]  table  metadata  session meta data
-- @treturn boolean|nil      session data
-- @treturn string           error message
function metatable:delete(name, key, current_time, metadata)
  if random() < CLEANUP_PROBABILITY then
    if metadata then
      SQL:put(STM_DELIM):putf(CLEANUP, self.table_meta, current_time)
    end
    SQL:put(STM_DELIM):putf(CLEANUP, self.table, current_time)
  end

  SQL:reset():putf(DELETE, self.table, key)

  return exec(self, SQL:tostring())
end


function metatable:read_metadata(audience, subject, current_time)
  local res = {}
  local t = exec(self, fmt(GET_META, self.table_meta, audience, subject, current_time))

  if not t then
    return nil, "not found"
  end
  for _, v in ipairs(t) do
    res[v["sid"]] = v["exp"]
  end

  return res
end

local storage = {}


---
-- Configuration
-- @section configuration


---
-- Postgres storage backend configuration
-- @field host the host to connect (defaults to `"127.0.0.1"`)
-- @field port the port to connect (defaults to `3306`)
-- @field socket the socket file to connect to (defaults to `nil`)
-- @field username the database username to authenticate (defaults to `nil`)
-- @field password password for authentication, may be required depending on server configuration
-- @field charset the character set used on the MySQL connection (defaults to `"ascii"`)
-- @field database the database name to connect
-- @field max_packet_size the upper limit for the reply packets sent from the MySQL server (defaults to 1 MB)
-- @field table_name name of database table to which to store session data (defaults to `"sessions"`)
-- @field table_name_meta name of database meta data table to which to store session meta data (defaults to `"sessions_meta"`)
-- @field connect_timeout controls the default timeout value used in TCP/unix-domain socket object's `connect` method
-- @field send_timeout controls the default timeout value used in TCP/unix-domain socket object's `send` method
-- @field read_timeout controls the default timeout value used in TCP/unix-domain socket object's `receive` method
-- @field keepalive_timeout controls the default maximal idle time of the connections in the connection pool
-- @field pool a custom name for the connection pool being used.
-- @field pool_size the size of the connection pool,
-- @field backlog a queue size to use when the connection pool is full (configured with @pool_size)
-- @field ssl enable ssl (defaults to `false`)
-- @field ssl_verify verify server certificate (defaults to `nil`)
-- @table configuration


---
-- Constructors
-- @section constructors


---
-- Create a MySQL / MariaDB storage.
--
-- This creates a new MySQL / MariaDB storage instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  mysql/mariadb storage @{configuration}
-- @treturn      table                  mysql/mariadb storage instance
function storage.new(configuration)
  local host              = configuration and configuration.host or DEFAULT_HOST
  local port              = configuration and configuration.port or DEFAULT_PORT
  local socket            = configuration and configuration.socket

  local username          = configuration and configuration.username
  local password          = configuration and configuration.password
  local charset           = configuration and configuration.charset or DEFAULT_CHARSET
  local database          = configuration and configuration.database
  local max_packet_size   = configuration and configuration.max_packet_size

  local table_name        = configuration and configuration.table or DEFAULT_TABLE
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

  if socket then
    return setmetatable({
      table = table_name,
      table_meta = table_name_meta or (table_name .. "_meta"),
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
    table_meta = table_name_meta or (table_name .. "_meta"), -- TODO: better name for table that is collecting
                                                             --       information about audiences and subjects
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
