local memcached    = require "resty.memcached"
local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local floor        = math.floor
local sleep        = ngx.sleep
local null         = ngx.null
local now          = ngx.now
local var          = ngx.var

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local defaults = {
    prefix       = var.session_memcache_prefix                 or "sessions",
    socket       = var.session_memcache_socket,
    host         = var.session_memcache_host                   or "127.0.0.1",
    port         = tonumber(var.session_memcache_port)         or 11211,
    uselocking   = enabled(var.session_memcache_uselocking     or true),
    spinlockwait = tonumber(var.session_memcache_spinlockwait) or 10000,
    maxlockwait  = tonumber(var.session_memcache_maxlockwait)  or 30,
    pool = {
        timeout  = tonumber(var.session_memcache_pool_timeout),
        size     = tonumber(var.session_memcache_pool_size)
    }
}

local memcache = {}

memcache.__index = memcache

function memcache.new(config)
    local c = config.memcache or defaults
    local p = c.pool          or defaults.pool
    local l = enabled(c.uselocking)
    if l == nil then
        l = defaults.uselocking
    end
    local self = {
        memcache     = memcached:new(),
        encode       = config.encoder.encode,
        decode       = config.encoder.decode,
        delimiter    = config.cookie.delimiter,
        prefix       = c.prefix or defaults.prefix,
        uselocking   = l,
        spinlockwait = tonumber(c.spinlockwait) or defaults.spinlockwait,
        maxlockwait  = tonumber(c.maxlockwait)  or defaults.maxlockwait,
        pool = {
            timeout = tonumber(p.timeout) or defaults.pool.timeout,
            size    = tonumber(p.size)    or defaults.pool.size
        }
    }
    local s = c.socket or defaults.socket
    if s and s ~= "" then
        self.socket = s
    else
        self.host = c.host or defaults.host
        self.port = c.port or defaults.port
    end
    return setmetatable(self, memcache)
end

function memcache:connect()
    local socket = self.socket
    if socket then
        return self.memcache:connect(socket)
    end
    return self.memcache:connect(self.host, self.port)
end

function memcache:set_keepalive()
    local pool = self.pool
    local timeout, size = pool.timeout, pool.size
    if timeout and size then
        return self.memcache:set_keepalive(timeout, size)
    end
    if timeout then
        return self.memcache:set_keepalive(timeout)
    end
    return self.memcache:set_keepalive()
end

function memcache:key(i)
    return concat({ self.prefix, self.encode(i) }, ":" )
end

function memcache:lock(k)
    if not self.uselocking then
        return true, nil
    end
    local s = self.spinlockwait
    local m = self.maxlockwait
    local w = s / 1000000
    local c = self.memcache
    local i = 1000000 / s * m
    local l = concat({ k, "lock" }, "." )
    for _ = 1, i do
        local ok = c:add(l, "1", m + 1)
        if ok then
            return true, nil
        end
        sleep(w)
    end
    return false, "no lock"
end

function memcache:unlock(k)
    if self.uselocking then
        return self.memcache:delete(concat({ k, "lock" }, "." ))
    end
    return true, nil
end

function memcache:get(k)
    local d = self.memcache:get(k)
    return d ~= null and d or nil
end

function memcache:set(k, d, l)
    return self.memcache:set(k, d, l)
end

function memcache:expire(k, l)
    self.memcache:touch(k, l)
end

function memcache:delete(k)
    self.memcache:delete(k)
end

-- Extracts the elements from the cookie-string (string-split essentially).
-- @param value (string) the string to split in the elements
-- @return array with the elements in order, or `nil` if the number of elements do not match expectations.
function memcache:cookie(value)
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

function memcache:open(cookie, lifetime)
    local c = self:cookie(cookie)
    if c and c[1] and c[2] and c[3] and c[4] then
        local ok, err = self:connect()
        if ok then
            local i, u, e, h = self.decode(c[1]), tonumber(c[2]), tonumber(c[3]), self.decode(c[4])
            local k = self:key(i)
            ok, err = self:lock(k)
            if ok then
                local d = self:get(k)
                if d then
                    self:expire(k, floor(lifetime))
                end
                self:unlock(k)
                self:set_keepalive()
                return i, u, e, d, h
            end
            self:set_keepalive()
            return nil, err
        else
            return nil, err
        end
    end
    return nil, "invalid"
end

function memcache:start(i)
    local ok, err = self:connect()
    if ok then
        ok, err = self:lock(self:key(i))
        self:set_keepalive()
    end
    return ok, err
end

-- Generates the cookie value.
-- Similar to 'save', but without writing to the storage.
-- @param id (string)
-- @param usebefore (number)
-- @param expires(number) lifetime (ttl) is calculated from this
-- @param data (string)
-- @param hash (string)
-- @return encoded cookie-string value, or nil+err
function memcache:touch(id, usebefore, expires, data, hash, close)
    local lifetime = floor(expires - now())

    if lifetime <= 0 then
        return nil, "expired"
    end

    return concat({ self.encode(id), usebefore, expires, self.encode(hash) }, self.delimiter)
end

function memcache:save(i, u, e, d, h, close)
    local ok, err = self:connect()
    if ok then
        local l, k = floor(e - now()), self:key(i)
        if l > 0 then
            ok, err = self:set(k, d, l)
            if close then
                self:unlock(k)
            end
            self:set_keepalive()
            if ok then
                return concat({ self.encode(i), u, e, self.encode(h) }, self.delimiter)
            end
            return ok, err
        end
        if close then
            self:unlock(k)
            self:set_keepalive()
        end
        return nil, "expired"
    end
    return ok, err
end

function memcache:close(i)
    local ok, err = self:connect()
    if ok then
        local k = self:key(i)
        self:unlock(k)
    end
    return ok, err
end

function memcache:destroy(i)
    local ok, err = self:connect()
    if ok then
        local k = self:key(i)
        self:delete(k)
        self:unlock(k)
        self:set_keepalive()
    end
    return ok, err
end

function memcache:ttl(i, ttl)
  local k = self:key(i)
  return self:expire(k, floor(ttl))
end

return memcache
