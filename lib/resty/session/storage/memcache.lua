local memcached    = require "resty.memcached"
local lock         = require "resty.lock"
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
local locks        = ngx.var.session_memcache_sessions_locks or "sessions_locks"
local server       = ngx.var.session_memcache_server or "127.0.0.1"
local port         = ngx.var.session_memcache_port or 11211

local memcache = {}

memcache.__index = memcache

function memcache.new()
    local m, err = memcached:new()
    m:connect(server, port)
    return setmetatable({ lock = lock:new(locks), memc = m }, memcache)
end

function memcache:open(cookie, lifetime)
    local r = split(cookie, "|", 3)
    if r and r[1] and r[2] and r[3] then
        local i, e, h, l = decode(r[1]), tonumber(r[2]), decode(r[3]), self.lock
        local ok, err = l:lock(i)
        if ok then
            local d, flags, err = self.memc:get(encode(i))        
            if not err and d then
                self.memc:set(encode(i), d, floor(lifetime))
            end
            l:unlock()
            return i, e, d, h
        end
        return nil, err
    end
    return nil, "invalid"
end

function memcache:start(i)
    self.lock:lock(i)
end

function memcache:save(i, e, d, h, close)
    local l = e - now()
    if l > 0 then
        local ok, err = self.memc:set(encode(i), d, floor(l))
        if close then
            self.lock:unlock()
        end
        if ok then
            return concat({ encode(i), e, encode(h) }, "|")
        end
        return nil, err
    end
    if close then
        self.lock:unlock()
    end
    return nil, "expired"
end

function memcache:destroy(i)
    self.memc:delete(encode(i))
    self.lock:unlock()
    self.memc:close()
end

return memcache