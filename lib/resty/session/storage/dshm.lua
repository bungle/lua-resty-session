local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local now          = ngx.now
local var          = ngx.var
local ngx          = ngx
local dshm         = require "resty.dshm"

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

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

    -- ngx.log(ngx.DEBUG, "Create Session With : ")
    -- ngx.log(ngx.DEBUG, " -- host : ", defaults.host)
    -- ngx.log(ngx.DEBUG, " -- port : ",defaults.port)
    -- ngx.log(ngx.DEBUG, " -- pool_size : ", defaults.pool_size)
    -- ngx.log(ngx.DEBUG, " -- pool_idle_timeout : ", defaults.pool_idle_timeout)

    local self = {
        store      = dshm:new(),
        encode     = config.encoder.encode,
        decode     = config.encoder.decode,
        delimiter  = config.cookie.delimiter,
        name       = defaults.store,
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
    local ok, err = self.store:set(...)
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
    local ok, err = self.store:get(...)
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
    local ok, err = self.store:touch(...)
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
    local ok, err = self.store:delete(...)
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
    -- ngx.log(ngx.DEBUG, "Open Session in progress ...")
    local r = self:cookie(cookie)
    if r and r[1] and r[2] and r[3] then
        local i, e, h = self.decode(r[1]), tonumber(r[2]), self.decode(r[3])
        local k = self:key(i)
        local d = self:get(concat({self.name , k}, ":"))
        if d then
            self:touch(concat({self.name , k}, ":"), lifetime)
            d = ngx.decode_base64(d)
        end
        -- ngx.log(ngx.DEBUG, "Open Session in done.")
        return i, e, d, h
    end
    -- ngx.log(ngx.DEBUG, "Open Session in done : invalid.")
    return nil, "invalid"
end

function shm:start(i)
    -- ngx.log(ngx.DEBUG, "Start Session done.")
    return true, nil
end

function shm:save(i, e, d, h, close)
    -- ngx.log(ngx.DEBUG, "Save Session in progress ...")
    local l = e - now()
    if l > 0 then
        local k = self:key(i)
        local ok, err = self:set(concat({self.name , k}, ":"), ngx.encode_base64(d), l)
        if ok then
            return concat({ k, e, self.encode(h) }, self.delimiter)
        end
        -- ngx.log(ngx.DEBUG, "Save Session in done.")
        return nil, err
    end
    -- ngx.log(ngx.DEBUG, "Save Session in done : expired.")
    return nil, "expired"
end

function shm:destroy(i)
    -- ngx.log(ngx.DEBUG, "Destroy Session in progress ...")
    self:delete(concat({self.name , self:key(i)}, ":"))
    -- ngx.log(ngx.DEBUG, "Destroy Session done.")
    return true, nil
end

return shm
