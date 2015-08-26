local memcached    = require "resty.memcached"
local utils        = require "resty.session.utils"
local split        = utils.split
local decode       = utils.decode
local encode       = utils.encode
local enabled      = utils.enabled
local concat       = table.concat
local tonumber     = tonumber
local now          = ngx.now
local sleep        = ngx.sleep
local setmetatable = setmetatable
local floor        = math.floor
local concat       = table.concat
local uselocking   = enabled(ngx.var.session_memcache_uselocking or true)
local host         = ngx.var.session_memcache_host or "127.0.0.1"
local port         = tonumber(ngx.var.session_memcache_port) or 11211
local spinlockwait = tonumber(ngx.var.session_memcache_spinlockwait) or 10000
local maxlockwait  = tonumber(ngx.var.session_memcache_maxlockwait) or 30
local prefix       = ngx.var.session_memcache_prefix or "sessions"
local pool_timeout = tonumber(ngx.var.session_memcache_pool_timeout)
local pool_size    = tonumber(ngx.var.session_memcache_pool_size)
local socket       = ngx.var.session_memcache_socket

local function lock(m, k)
    if not uselocking then
        return true, nil
    end
    local l = concat({ k, "lock" }, "." )
    for _ = 0, 1000000 / spinlockwait * maxlockwait do
        local ok = m:add(l, "1", maxlockwait + 1)
        if ok then
            return true, nil
        end
        sleep(spinlockwait / 1000000)
    end
    return false, "no lock"
end

local function unlock(m, k)
    if uselocking then
        m:delete(concat({ k, "lock" }, "." ))
    end
end

local function connect(m)
    if socket then
        return m:connect(socket)
    end
    return m:connect(host, port)
end

local function disconnect(m)
    if pool_timeout then
        if pool_size then
            return m:set_keepalive(pool_timeout, pool_size)
        end
        return m:set_keepalive(pool_timeout)
    end
    return m:set_keepalive()
end

local memcache = {}

memcache.__index = memcache

function memcache.new()
    return setmetatable({ memc = memcached:new() }, memcache)
end

function memcache:open(cookie, lifetime)
    local c = split(cookie, "|", 3)
    if c and c[1] and c[2] and c[3] then
        local m = self.memc
        local ok, err = connect(m)
        if ok then
            local i, e, h = decode(c[1]), tonumber(c[2]), decode(c[3])
            local k = concat({ prefix, encode(i) }, ":" )
            ok, err = lock(m, k)
            if ok then
                local d = m:get(k)
                if d then
                    m:touch(k, floor(lifetime))
                end
                unlock(m, k)
                disconnect(m)
                return i, e, d, h
            end
            disconnect(m)
            return nil, err
        else
            return nil, err
        end
    end
    return nil, "invalid"
end

function memcache:start(i)
    local m = self.memc
    local ok, err = connect(m)
    if ok then
        ok, err = lock(m, concat({ prefix, encode(i) }, ":" ))
        disconnect(m)
    end
    return ok, err
end

function memcache:save(i, e, d, h, close)
    local m = self.memc
    local ok, err = connect(m)
    if ok then
        local l, k = e - now(), concat({ prefix, encode(i) }, ":" )
        if l > 0 then
            ok, err = m:set(k, d, floor(l))
            if close then
                unlock(m, k)
            end
            disconnect(m)
            if ok then
                return concat({ encode(i), e, encode(h) }, "|")
            end
            return ok, err
        end
        if close then
            unlock(m, k)
            disconnect(m)
        end
        return nil, "expired"
    end
    return ok, err

end

function memcache:destroy(i)
    local m = self.memc
    local ok, err = connect(m)
    if ok then
        local k = concat({ prefix, encode(i) }, ":" )
        m:delete(k)
        unlock(m, k)
        disconnect(m)
    end
    return ok, err
end

return memcache