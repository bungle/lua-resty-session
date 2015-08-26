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

local function noop()
    return true, nil
end

local function lock_real(r, k)
    local spinlockwait, maxlockwait = spinlockwait, maxlockwait
    local l = concat({ k, "lock" }, "." )
    for _ = 0, 1000000 / spinlockwait * maxlockwait do
        local ok = r:setnx(l, '1')
        if ok then
            return r:expire(l, maxlockwait + 1)
        end
        sleep(spinlockwait / 1000000)
    end
    return false, "no lock"
end

local function unlock_real(r, k)
    return r:del(concat({ k, "lock" }, "." ))
end

local function connect_socket(r)
    return r:connect(socket)
end

local function connect_host(r)
    return r:connect(host, port)
end

local function disconnect_two(r)
    return r:set_keepalive(pool_timeout, pool_size)
end

local function disconnect_one(r)
    return r:set_keepalive(pool_timeout)
end

local function disconnect_zero(r)
    return r:set_keepalive()
end

local connect = socket     and connect_socket or connect_host
local lock    = uselocking and lock_real      or noop
local unlock  = uselocking and unlock_real    or noop
local disconnect

if pool_timeout and pool_size then
    disconnect = disconnect_two
elseif pool_timeout then
    disconnect = disconnect_one
else
    disconnect = disconnect_zero
end

local redis = {}

redis.__index = redis

function redis.new()
    return setmetatable({ redis = red:new() }, redis)
end

function redis:open(cookie, lifetime)
    local c = split(cookie, "|", 3)
    if c and c[1] and c[2] and c[3] then
        local r = self.redis
        local ok, err = connect(r)
        if ok then
            local i, e, h = decode(c[1]), tonumber(c[2]), decode(c[3])
            local k = concat({ prefix, encode(i) }, ":" )
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
    local r = self.redis
    local ok, err = connect(r)
    if ok then
        ok, err = lock(r, concat({ prefix, encode(i) }, ":" ))
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
    local r = self.redis
    local ok, err = connect(r)
    if ok then
        local k = concat({ prefix, encode(i) }, ":" )
        r:del(k)
        unlock(r, k)
        disconnect(r)
    end
    return ok, err
end

return redis