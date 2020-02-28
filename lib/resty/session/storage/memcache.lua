local memcached    = require "resty.memcached"
local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local sleep        = ngx.sleep
local null         = ngx.null
local var          = ngx.var

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local defaults = {
    prefix       = var.session_memcache_prefix                     or "sessions",
    socket       = var.session_memcache_socket,
    host         = var.session_memcache_host                       or "127.0.0.1",
    port         = tonumber(var.session_memcache_port,         10) or 11211,
    uselocking   = enabled(var.session_memcache_uselocking         or true),
    spinlockwait = tonumber(var.session_memcache_spinlockwait, 10) or 150,
    maxlockwait  = tonumber(var.session_memcache_maxlockwait,  10) or 30,
    pool = {
        timeout  = tonumber(var.session_memcache_pool_timeout, 10),
        size     = tonumber(var.session_memcache_pool_size,    10),
    },
}

local storage = {}

storage.__index = storage

function storage.new(session)
    local config  = session.memcache or defaults
    local pool    = config.pool      or defaults.pool
    local locking = enabled(config.uselocking)
    if locking == nil then
        locking = defaults.uselocking
    end

    local self = {
        memcache     = memcached:new(),
        prefix       = config.prefix                     or defaults.prefix,
        uselocking   = locking,
        spinlockwait = tonumber(config.spinlockwait, 10) or defaults.spinlockwait,
        maxlockwait  = tonumber(config.maxlockwait,  10) or defaults.maxlockwait,
        pool = {
            timeout = tonumber(pool.timeout,         10) or defaults.pool.timeout,
            size    = tonumber(pool.size,            10) or defaults.pool.size,
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
    local socket = self.socket
    if socket then
        return self.memcache:connect(socket)
    end
    return self.memcache:connect(self.host, self.port)
end

function storage:set_keepalive()
    local pool    = self.pool
    local timeout = pool.timeout
    local size    = pool.size

    if timeout and size then
        return self.memcache:set_keepalive(timeout, size)
    end

    if timeout then
        return self.memcache:set_keepalive(timeout)
    end

    return self.memcache:set_keepalive()
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
        local ok = self.memcache:add(lock_key, self.token, lock_ttl)
        if ok then
            self.locked = true
            return true
        end

        sleep(waittime)
    end

    return false, "unable to acquire a session lock"
end

function storage:unlock(key)
    if not self.uselocking or not self.locked then
        return true
    end

    local lock_key = concat({ key, "lock" }, "." )
    local token = self:get(lock_key)

    if token == self.token then
        self.memcache:delete(lock_key)
        self.locked = nil
    end
end

function storage:get(key)
    local data, err = self.memcache:get(key)
    if not data then
        return nil, err
    end

    if data == null then
        return nil
    end

    return data
end

function storage:set(key, data, ttl)
    return self.memcache:set(key, data, ttl)
end

function storage:expire(key, ttl)
    return self.memcache:touch(key, ttl)
end

function storage:delete(key)
    return self.memcache:delete(key)
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

    local key = self:key(id)

    ok, err = self:lock(key)

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
