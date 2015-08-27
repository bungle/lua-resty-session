local lock         = require "resty.lock"
local utils        = require "resty.session.utils"
local split        = utils.split
local decode       = utils.decode
local encode       = utils.encode
local concat       = table.concat
local tonumber     = tonumber
local now          = ngx.now
local shared       = ngx.shared
local sessions     = ngx.var.session_shm_sessions       or "sessions"
local locks        = ngx.var.session_shm_sessions_locks or "sessions_locks"
local setmetatable = setmetatable

local shm = {}

shm.__index = shm

function shm.new()
    return setmetatable({ lock = lock:new(locks), sessions = shared[sessions] }, shm)
end

function shm:open(cookie, lifetime)
    local r = split(cookie, "|", 3)
    if r and r[1] and r[2] and r[3] then
        local i, e, h = decode(r[1]), tonumber(r[2]), decode(r[3])
        if self.lock then
            local ok, err = self.lock:lock(i)
            if ok then
                local s = self.sessions
                local d = s:get(i)
                s:set(i, d, lifetime)
                self.lock:unlock()
                return i, e, d, h
            end
            return nil, err
        else
            local s = self.sessions
            local d = s:get(i)
            s:set(i, d, lifetime)
            return i, e, d, h
        end
    end
    return nil, "invalid"
end

function shm:start(i)
    if self.lock then
        return self.lock:lock(i)
    end
    return true, nil
end

function shm:save(i, e, d, h, close)
    local l = e - now()
    if l > 0 then
        local ok, err = self.sessions:set(i, d, l)
        if self.lock and close then
            self.lock:unlock()
        end
        if ok then
            return concat({ encode(i), e, encode(h) }, "|")
        end
        return nil, err
    end
    if self.lock and close then
        self.lock:unlock()
    end
    return nil, "expired"
end

function shm:destroy(i)
    self.sessions:delete(i)
    if self.lock then
        self.lock:unlock()
    end
    return true, nil
end

return shm