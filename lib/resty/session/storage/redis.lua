local redis        = require "resty.redis"

local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local sleep        = ngx.sleep
local null         = ngx.null
local var          = ngx.var

local UNLOCK = [[
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
]]

local function enabled(value)
    if value == nil then return nil end
    return value == true or (value == "1" or value == "true" or value == "on")
end

local defaults = {
    prefix       = var.session_redis_prefix                      or "sessions",
    database     = tonumber(var.session_redis_database,     10)  or 0,
    socket       = var.session_redis_socket,
    host         = var.session_redis_host                        or "127.0.0.1",
    port         = tonumber(var.session_redis_port,         10)  or 6379,
    auth         = var.session_redis_auth,
    uselocking   = enabled(var.session_redis_uselocking          or true),
    spinlockwait = tonumber(var.session_redis_spinlockwait, 10)  or 150,
    maxlockwait  = tonumber(var.session_redis_maxlockwait,  10)  or 30,
    pool = {
        timeout  = tonumber(var.session_redis_pool_timeout, 10),
        size     = tonumber(var.session_redis_pool_size,    10)
    },
    ssl          = enabled(var.session_redis_ssl)                or false,
    ssl_verify   = enabled(var.session_redis_ssl_verify)         or false,
    server_name  = var.session_redis_server_name,
}

local storage = {}

storage.__index = storage

function storage.new(session)
    local config = session.redis or defaults
    local pool   = config.pool   or defaults.pool

    local locking = enabled(config.uselocking)
    if locking == nil then
        locking = defaults.uselocking
    end

    local self = {
        redis         = redis:new(),
        auth          = config.auth                       or defaults.auth,
        prefix        = config.prefix                     or defaults.prefix,
        database      = tonumber(config.database,     10) or defaults.database,
        uselocking    = locking,
        spinlockwait  = tonumber(config.spinlockwait, 10) or defaults.spinlockwait,
        maxlockwait   = tonumber(config.maxlockwait,  10) or defaults.maxlockwait,
        pool = {
            timeout   = tonumber(pool.timeout,        10) or defaults.pool.timeout,
            size      = tonumber(pool.size,           10) or defaults.pool.size,
        },
        connect_opts = {
          ssl         = config.ssl                        or defaults.ssl,
          ssl_verify  = config.ssl_verify                 or defaults.ssl_verify,
          server_name = config.server_name                or defaults.server_name,
        },
    }

    local socket = config.socket or defaults.socket
    if socket and socket ~= "" then
        self.socket = socket
    else
        self.host = config.host or defaults.host
        self.port = config.port or defaults.port
    end

    return setmetatable(self, storage)
end

function storage:connect()
    local ok, err
    if self.socket then
        ok, err = self.redis:connect(self.socket)
    else
        ok, err = self.redis:connect(self.host, self.port, self.connect_opts)
    end

    if not ok then
        return nil, err
    end

    if self.auth and self.auth ~= "" and self.redis:get_reused_times() == 0 then
        ok, err = self.redis:auth(self.auth)
        if not ok then
            return nil, err
        end
    end

    if self.database ~= 0 then
        ok, err = self.redis:select(self.database)
    end

    return ok, err
end

function storage:set_keepalive()
    local pool    = self.pool
    local timeout = pool.timeout
    local size    = pool.size

    if timeout and size then
        return self.redis:set_keepalive(timeout, size)
    end

    if timeout then
        return self.redis:set_keepalive(timeout)
    end

    return self.redis:set_keepalive()
end

function storage:key(id)
    return concat({ self.prefix, id }, ":" )
end

function storage:lock(key)
    if not self.uselocking or self.locked then
        return true
    end

    if not self.token then
        self.token = var.request_id
    end

    local lock_key = concat({ key, "lock" }, "." )
    local lock_ttl = self.maxlockwait + 1
    local attempts = (1000 / self.spinlockwait) * self.maxlockwait
    local waittime = self.spinlockwait / 1000

    for _ = 1, attempts do
        local ok = self.redis:set(lock_key, self.token, "EX", lock_ttl, "NX")
        if ok ~= null then
            self.locked = true
            return true
        end

        sleep(waittime)
    end

    return false, "unable to acquire a session lock"
end

function storage:unlock(key)
    if not self.uselocking or not self.locked then
        return
    end

    local lock_key = concat({ key, "lock" }, "." )

    self.redis:eval(UNLOCK, 1, lock_key, self.token)
    self.locked = nil
end

function storage:get(key)
    local data, err = self.redis:get(key)
    if not data then
        return nil, err
    end

    if data == null then
        return nil
    end

    return data
end

function storage:set(key, data, lifetime)
    return self.redis:setex(key, lifetime, data)
end

function storage:expire(key, lifetime)
    return self.redis:expire(key, lifetime)
end

function storage:delete(key)
    return self.redis:del(key)
end

function storage:open(id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:lock(key)
    if not ok then
        self:set_keepalive()
        return nil, err
    end

    local data
    data, err = self:get(key)

    self:unlock(key)
    self:set_keepalive()

    return data, err
end

function storage:start(id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    ok, err = self:lock(self:key(id))

    self:set_keepalive()

    return ok, err
end

function storage:save(id, ttl, data, close)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:set(key, data, ttl)

    if close then
        self:unlock(key)
    end

    self:set_keepalive()

    if not ok then
        return nil, err
    end

    return true
end

function storage:close(id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    self:unlock(key)
    self:set_keepalive()

    return true
end

function storage:destroy(id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    local ok, err = self:delete(key)

    self:unlock(key)
    self:set_keepalive()

    return ok, err
end

function storage:ttl(id, ttl, close)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:expire(key, ttl)

    if close then
        self:unlock(key)
    end

    self:set_keepalive()

    return ok, err
end

return storage
