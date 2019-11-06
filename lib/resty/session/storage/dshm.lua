local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local now          = ngx.now
local var          = ngx.var
local ngx          = ngx
local dshm         = require "resty.dshm"

local defaults = {
    store      = var.session_dshm_store or "sessions",
    host       = var.session_dshm_host or "127.0.0.1",
    port       = tonumber(var.session_dshm_port) or 4321,
    pool_size  = tonumber(var.session_dshm_pool_size) or 100,
    pool_idle_timeout = tonumber(var.session_dshm_pool_idle_timeout) or 1000
}

local shm = {}

shm.__index = shm

function shm.new(config)
    local c = config.shm or defaults
    local m = c.store or defaults.store

    local self = {
        store      = dshm:new(),
        encode     = config.encoder.encode,
        decode     = config.encoder.decode,
        delimiter  = config.cookie.delimiter,
        name       = m,
        host       = defaults.host,
        port       = defaults.port,
        pool_size  = defaults.pool_size,
        pool_idle_timeout = defaults.pool_idle_timeout
    }
    return setmetatable(self, shm)
end

function shm:connect()
    return self.store:connect(self.host, self.port)
end

function shm:setkeepalive()
    return self.store:set_keepalive(self.pool_idle_timeout, self.pool_size)
end

function shm:set(...)
    local _, err = self:connect()
    if err then
        return nil, err
    end
    local ok
    ok, err = self.store:set(...)
    self:setkeepalive()
    if err then
        return nil, err
    end
    return ok, nil
end

function shm:get(...)
    local _, err = self:connect()
    if err then
        return nil, err
    end
    local ok
    ok, err = self.store:get(...)
    self:setkeepalive()
    if err then
        return nil, err
    end
    return ok, nil
end

function shm:touch(...)
    local _, err = self:connect()
    if err then
        return nil, err
    end
    local ok
    ok, err = self.store:touch(...)
    self:setkeepalive()
    if err then
        return nil, err
    end
    return ok, nil
end

function shm:delete(...)
    local _, err = self:connect()
    if err then
        return nil, err
    end
    local ok
    ok, err = self.store:delete(...)
    self:setkeepalive()
    if err then
        return nil, err
    end
    return ok, nil
end

function shm:key(i)
    return self.encode(i)
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
        local k = self:key(i)
        local d = self:get(concat({self.name , k}, ":"))
        if d then
            self:touch(concat({self.name , k}, ":"), lifetime)
            d = ngx.decode_base64(d)
        end

        return i, e, d, h
    end
    return nil, "invalid"
end

function shm:start(_) -- luacheck: ignore
    return true, nil
end

function shm:save(i, e, d, h, _)
    local l = e - now()
    if l > 0 then
        local k = self:key(i)
        local ok, err = self:set(concat({self.name , k}, ":"), ngx.encode_base64(d), l)
        if ok then
            return concat({ k, e, self.encode(h) }, self.delimiter)
        end
        return nil, err
    end
    return nil, "expired"
end

function shm:destroy(i)
    self:delete(concat({self.name , self:key(i)}, ":"))
    return true, nil
end

return shm
