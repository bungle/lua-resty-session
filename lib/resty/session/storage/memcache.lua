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
local uselocking   = ngx.var.session_memcache_uselocking or true
local server       = ngx.var.session_memcache_server or "127.0.0.1"
local port         = ngx.var.session_memcache_port or 11211
local spinlockwait = ngx.var.session_memcache_spinlockwait or 10000
local maxlockwait  = ngx.var.session_memcache_maxlockwait or 30
local lockprefix   = ngx.var.session_memcache_lockprefix or "session-memcache-lock"
local memcache = {}

memcache.__index = memcache

local function lock(m, i)
    if uselocking then
        for j = 0, (1000000 / spinlockwait) * maxlockwait do
            local ok, err = m.memc:add(lockprefix .. "." .. encode(i), '1', maxlockwait+1)
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

function unlock(m, i)
    if uselocking then
        m.memc:delete(lockprefix .. "." .. encode(i))
        m.locked = false
    end
    return true, nil
end

function memcache.new()
    local m, err = memcached:new()
    m:connect(server, port)
    return setmetatable({ memc = m, locked = false }, memcache)
end

function memcache:open(cookie, lifetime)
    local r = split(cookie, "|", 3)
    if r and r[1] and r[2] and r[3] then
        local i, e, h = decode(r[1]), tonumber(r[2]), decode(r[3])
        local ok, err = lock(self, i)
        if ok then
            local d, flags, err = self.memc:get(encode(i))        
            if not err and d then
                self.memc:set(encode(i), d, floor(lifetime))
            end
            unlock(self, i)
            return i, e, d, h
        end
        return nil, err
    end
    return nil, "invalid"
end

function memcache:start(i)
    lock(self, i)
end

function memcache:save(i, e, d, h, close)
    local l = e - now()
    if l > 0 then
        local ok, err = self.memc:set(encode(i), d, floor(l))
        if close then
            unlock(self, i)
        end
        if ok then
            return concat({ encode(i), e, encode(h) }, "|")
        end
        return nil, err
    end
    if close then
        unlock(self, i)
    end
    return nil, "expired"
end

function memcache:destroy(i)
    self.memc:delete(encode(i))
    unlock(self, i)
    self.memc:close()
end

return memcache