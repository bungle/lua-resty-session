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

-- Extracts the elements from the cookie-string (string-split essentially).
-- @param value (string) the string to split in the elements
-- @return array with the elements in order, or `nil` if the number of elements do not match expectations.
function shm:cookie(value)
    local size = 4
    local result, delim = {}, self.delimiter
    local count, pos = 1, 1
    local match_start, match_end = value:find(delim, 1, true)
    while match_start do
        if count == size then
            return nil  -- too many elements
        end
        result[count] = value:sub(pos, match_end - 1)
        count = count + 1
        pos = match_end + 1
        match_start, match_end = value:find(delim, pos, true)
    end
    if count ~= size then
        return nil  -- too little elements
    end
    result[size] = value:sub(pos)
    return result
end

function shm:open(cookie)
    local r = self:cookie(cookie)
    if r and r[1] and r[2] and r[3] and r[4] then
        local i, u, e, h = self.decode(r[1]), tonumber(r[2]), tonumber(r[3]), self.decode(r[4])
        local k = self:key(i)
        local d = self:get(concat({self.name , k}, ":"))
        if d then
            d = ngx.decode_base64(d)
        end

        return i, u, e, d, h
    end
    return nil, "invalid"
end

function shm:start(_) -- luacheck: ignore
    return true, nil
end

-- Generates the cookie value.
-- Similar to 'save', but without writing to the storage.
-- @param id (string)
-- @param usebefore (number)
-- @param expires(number) lifetime (ttl) is calculated from this
-- @param data (string)
-- @param hash (string)
-- @return encoded cookie-string value, or nil+err
function shm:touch(id, usebefore, expires, data, hash, close)
    local lifetime = math.floor(expires - now())

    if lifetime <= 0 then
        return nil, "expired"
    end

    return concat({ self:key(id), usebefore, expires, self.encode(hash) }, self.delimiter)
end

function shm:save(i, u, e, d, h, _)
    local l = e - now()
    if l > 0 then
        local k = self:key(i)
        local ok, err = self:set(concat({self.name , k}, ":"), ngx.encode_base64(d), l)
        if ok then
            return concat({ k, u, e, self.encode(h) }, self.delimiter)
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
