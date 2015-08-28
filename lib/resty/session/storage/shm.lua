local lock         = require "resty.lock"
local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local now          = ngx.now
local shared       = ngx.shared

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local defaults = {
    store      = ngx.var.session_shm_store or "sessions",
    locks      = ngx.var.session_shm_locks or "sessions_locks",
    uselocking = enabled(ngx.var.session_shm_uselocking or true),
    lock       = {
        exptime    = tonumber(ngx.var.session_shm_lock_exptime) or 30,
        timeout    = tonumber(ngx.var.session_shm_lock_timeout) or 5,
        step       = tonumber(ngx.var.session_shm_lock_step) or 0.001,
        ratio      = tonumber(ngx.var.session_shm_lock_ratio) or 2,
        max_step   = tonumber(ngx.var.session_shm_lock_max_step) or 0.5,
    }
}

local shm = {}

shm.__index = shm

function shm.new(config)
    local c = config.shm or defaults
    local l = enabled(c.uselocking)
    if l == nil then
        l = defaults.uselocking
    end
    local self = {
        store      = shared[c.store or defaults.store],
        encode     = config.encoder.encode,
        decode     = config.encoder.decode,
        delimiter  = config.cookie.delimiter,
        uselocking = l
    }
    if l then
        local x = c.lock or defaults.lock
        local s = {
            exptime   = tonumber(x.exptime)  or defaults.exptime,
            timeout   = tonumber(x.timeout)  or defaults.timeout,
            step      = tonumber(x.step)     or defaults.step,
            ratio     = tonumber(x.ratio)    or defaults.ratio,
            max_step  = tonumber(x.max_step) or defaults.max_step
        }
        self.locks = lock:new(c.locks or defaults.locks, s)
    end
    return setmetatable(self, shm)
end

function shm:cookie(c)
    local r, d = {}, self.delimiter
    local i, p, s, e = 1, 1, c:find(d, 1, true)
    while s do
        if i > 2 then
            return nil
        end
        r[i] = c:sub(p, e - 1)
        i, p = i + 1, e + 1
        s, e = c:find(d, p, true)
    end
    if i ~= 3 then
        return nil
    end
    r[3] = c:sub(p)
    return r
end

function shm:open(cookie, lifetime)
    local r = self:cookie(cookie)
    if r and r[1] and r[2] and r[3] then
        local i, e, h = self.decode(r[1]), tonumber(r[2]), self.decode(r[3])
        if self.uselocking then
            local l = self.locks
            local ok, err = l:lock(i)
            if ok then
                local s = self.store
                local d = s:get(i)
                s:set(i, d, lifetime)
                l:unlock()
                return i, e, d, h
            end
            return nil, err
        else
            local s = self.store
            local d = s:get(i)
            s:set(i, d, lifetime)
            return i, e, d, h
        end
    end
    return nil, "invalid"
end

function shm:start(i)
    if self.uselocking then
        return self.locks:lock(i)
    end
    return true, nil
end

function shm:save(i, e, d, h, close)
    local l = e - now()
    if l > 0 then
        local ok, err = self.store:set(i, d, l)
        if self.uselocking and close then
            self.locks:unlock()
        end
        if ok then
            return concat({ self.encode(i), e, self.encode(h) }, self.delimiter)
        end
        return nil, err
    end
    if self.uselocking and close then
        self.locks:unlock()
    end
    return nil, "expired"
end

function shm:destroy(i)
    self.store:delete(i)
    if self.uselocking then
        self.locks:unlock()
    end
    return true, nil
end

return shm