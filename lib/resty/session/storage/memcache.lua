local memcached    = require "resty.memcached"
local utils        = require "resty.session.utils"
local split        = utils.split
local decode       = utils.decode
local encode       = utils.encode
local concat       = table.concat
local tonumber     = tonumber
local now          = ngx.now
local shared       = ngx.shared
local setmetatable = setmetatable
local floor        = math.floor
local concat       = table.concat
local enabled      = utils.enabled
local uselocking   = enabled(ngx.var.session_memcache_uselocking or true)
local host         = ngx.var.session_memcache_host or "127.0.0.1"
local port         = tonumber(ngx.var.session_memcache_port) or 11211
local spinlockwait = tonumber(ngx.var.session_memcache_spinlockwait) or 10000
local maxlockwait  = tonumber(ngx.var.session_memcache_maxlockwait) or 30
local prefix       = ngx.var.session_memcache_prefix or "sessions"
local pool_timeout = tonumber(ngx.var.session_memcache_pool_timeout) or 20
local pool_size    = tonumber(ngx.var.session_memcache_pool_size) or 10
local socket       = ngx.var.session_memcache_socket
local memcache = {}

memcache.__index = memcache

local function lock(m, sk)
    if uselocking then
        local lk = concat({ sk, "lock" }, "." )
        for j = 0, (1000000 / spinlockwait) * maxlockwait do
            local ok, err = m.memc:add(lk, '1', maxlockwait+1)
            if ok then
                m.locked = true
                return true, nil
            end
            ngx.sleep(spinlockwait / 1000000)
        end
        return false, "no lock"
    end
    return true, nil
end

local function unlock(m, sk)
    if uselocking then
        local lk = concat({ sk, "lock" }, "." )
        m.memc:delete(lk)
        m.locked = false
    end
    return true, nil
end

local function connect(m)
    if socket then
        m.memc:connect(socket)
    else
        m.memc:connect(host, port)
    end
end

local function disconnect(m)
    --m.memc:close()
    m.memc:set_keepalive(pool_timeout, pool_size)
end

function memcache.new()
    return setmetatable({ memc = memcached:new(), locked = false }, memcache)
end

function memcache:open(cookie, lifetime)
    local r = split(cookie, "|", 3)
    if r and r[1] and r[2] and r[3] then
        local i, e, h = decode(r[1]), tonumber(r[2]), decode(r[3])
        local sk = concat({ prefix, encode(i) }, ":" )
        connect(self)
        local ok, err = lock(self, sk)
        if ok then
            local d, flags, err = self.memc:get(sk)
            if not err and d then
                self.memc:touch(sk, floor(lifetime))
            end
            unlock(self, sk)
            disconnect(self)
            return i, e, d, h
        end
        disconnect(self)
        return nil, err
    end
    return nil, "invalid"
end

function memcache:start(i)
    local sk = concat({ prefix, encode(i) }, ":" )
    connect(self)
    lock(self, sk)
    disconnect(self)
end

function memcache:save(i, e, d, h, close)
    local l = e - now()
    local sk = concat({ prefix, encode(i) }, ":" )
    connect(self)
    if l > 0 then
        local ok, err = self.memc:set(sk, d, floor(l))
        if close then
            unlock(self, sk)
        end
        disconnect(self)
        if ok then
            return concat({ encode(i), e, encode(h) }, "|")
        end
        return nil, err
    end
    if close then
        unlock(self, sk)
        disconnect(self)
    end
    return nil, "expired"
end

function memcache:destroy(i)
    local sk = concat({ prefix, encode(i) }, ":" )
    connect(self)
    self.memc:delete(sk)
    unlock(self, sk)
    disconnect(self)
end

return memcache