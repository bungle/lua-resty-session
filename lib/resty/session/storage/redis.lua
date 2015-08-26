local red          = require "resty.redis"
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
local uselocking   = enabled(ngx.var.session_redis_uselocking or true)
local host         = ngx.var.session_redis_host or "127.0.0.1"
local port         = tonumber(ngx.var.session_redis_port) or 6379
local spinlockwait = tonumber(ngx.var.session_redis_spinlockwait) or 10000
local maxlockwait  = tonumber(ngx.var.session_redis_maxlockwait) or 30
local prefix       = ngx.var.session_redis_prefix or "sessions"
local pool_timeout = tonumber(ngx.var.session_redis_pool_timeout)
local pool_size    = tonumber(ngx.var.session_redis_pool_size)
local socket       = ngx.var.session_redis_socket

local function lock(r, k)
    if not uselocking then
        return true, nil
    end
    local l = concat({ k, "lock" }, "." )
    for _ = 0, (1000000 / spinlockwait) * maxlockwait do
        local ok = r:setnx(l, '1')
        if ok then
            return r:expire(l, maxlockwait + 1)
        end
        sleep(spinlockwait / 1000000)
    end
    return false, "no lock"
end

local function unlock(r, k)
    if uselocking then
        r:del(concat({ k, "lock" }, "." ))
    end
end

local function connect(r)
    return socket and r:connect(socket) or r:connect(host, port)
end

local function disconnect(r)
    if pool_timeout then
        if pool_size then
            r:set_keepalive(pool_timeout, pool_size)
        else
            r:set_keepalive(pool_timeout)
        end
    else
        r:set_keepalive()
    end
end

local redis = {}

redis.__index = redis

function redis.new()
    return setmetatable({ redis = red:new() }, redis)
end

function redis:open(cookie, lifetime)
    local c = split(cookie, "|", 3)
    if c and c[1] and c[2] and c[3] then
        local i, e, h = decode(c[1]), tonumber(c[2]), decode(c[3])
        local k = concat({ prefix, encode(i) }, ":" )
        local r = self.redis
        local ok, err = connect(r)
        if ok then
            ok, err = lock(r, k)
            if ok then
                local d = r:get(k)
                if d then
                    r:expire(k, floor(lifetime))
                end
                unlock(r, k)
                disconnect(r)
                return i, e, d, h
            end
            disconnect(r)
            return nil, err
        else
            return nil, err
        end
    end
    return nil, "invalid"
end

function redis:start(i)
    local r, k = self.redis, concat({ prefix, encode(i) }, ":" )
    local ok, err = connect(r)
    if ok then
        ok, err = lock(r, k)
        disconnect(r)
    end
    return ok, err
end

function redis:save(i, e, d, h, close)
    local r = self.redis
    local ok, err = connect(r)
    if ok then
        local l, k = e - now(), concat({ prefix, encode(i) }, ":" )
        if l > 0 then
            ok, err = r:setex(k, floor(l), d)
            if close then
                unlock(r, k)
            end
            disconnect(r)
            if ok then
                return concat({ encode(i), e, encode(h) }, "|")
            end
            return ok, err
        end
        if close then
            unlock(r, k)
            disconnect(r)
        end
        return nil, "expired"
    end
    return ok, err
end

function redis:destroy(i)
    local r, k = self.redis, concat({ prefix, encode(i) }, ":" )
    local ok, err = connect(r)
    if ok then
        r:del(k)
        unlock(r, k)
        disconnect(r)
    end
    return ok, err
end

return redis