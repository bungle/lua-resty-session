local lock         = require "resty.lock"
local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local now          = ngx.now
local var          = ngx.var
local shared       = ngx.shared

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local defaults = {
    store      = var.session_shm_store or "sessions",
    uselocking = enabled(var.session_shm_uselocking or true),
    lock       = {
        exptime  = tonumber(var.session_shm_lock_exptime)  or 30,
        timeout  = tonumber(var.session_shm_lock_timeout)  or 5,
        step     = tonumber(var.session_shm_lock_step)     or 0.001,
        ratio    = tonumber(var.session_shm_lock_ratio)    or 2,
        max_step = tonumber(var.session_shm_lock_max_step) or 0.5,
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
    local m = c.store or defaults.store
    local self = {
        store      = shared[m],
        encode     = config.encoder.encode,
        decode     = config.encoder.decode,
        delimiter  = config.cookie.delimiter,
        uselocking = l
    }
    if l then
        local x = c.lock or defaults.lock
        local s = {
            exptime  = tonumber(x.exptime)  or defaults.exptime,
            timeout  = tonumber(x.timeout)  or defaults.timeout,
            step     = tonumber(x.step)     or defaults.step,
            ratio    = tonumber(x.ratio)    or defaults.ratio,
            max_step = tonumber(x.max_step) or defaults.max_step
        }
        self.lock = lock:new(m, s)
    end
    return setmetatable(self, shm)
end

function shm:key(id)
    return self.encode(id)
end

-- Extracts the elements from the cookie-string (string-split essentially).
-- @param value (string) the string to split in the elements
-- @return array with the elements in order, or `nil` if the number of elements do not match expectations.
function shm:cookie(value)
    local result, delim = {}, self.delimiter
    local count, pos = 1, 1
    local match_start, match_end = value:find(delim, 1, true)
    while match_start do
        if count > 2 then
            return nil  -- too many elements
        end
        result[count] = value:sub(pos, match_end - 1)
        count, pos = count + 1, match_end + 1
        match_start, match_end = value:find(delim, pos, true)
    end
    if count ~= 3 then
        return nil  -- too little elements (3 expected)
    end
    result[3] = value:sub(pos)
    return result
end

-- Opens session and writes it to the store. Returns 4 decoded data elements from the cookie-string.
-- @param value (string) the cookie string containing the encoded data.
-- @param lifetime (number) lifetime in seconds of the data in the store (ttl)
-- @return id (string), expires(number), data (string), hash (string).
function shm:open(value, lifetime)
    local r = self:cookie(value)
    if r and r[1] and r[2] and r[3] then
        local id, expires, hash = self.decode(r[1]), tonumber(r[2]), self.decode(r[3])
        local key = self:key(id)
        if self.uselocking then
            local l = self.lock
            local ok, err = l:lock(concat{key, ".lock"})
            if ok then
                local cshm = self.store
                local data = cshm:get(key)
                cshm:set(key, data, lifetime)
                l:unlock()
                return id, expires, data, hash
            end
            return nil, err
        else
            local cshm = self.store
            local data = cshm:get(key)
            cshm:set(key, data, lifetime)
            return id, expires, data, hash
        end
    end
    return nil, "invalid"
end

-- acquire locks if required
function shm:start(id)
    if self.uselocking then
        return self.lock:lock(concat{self:key(id), ".lock"})
    end
    return true, nil
end

-- Saves the session data to the SHM.
-- server-side in this case.
-- @param id (string)
-- @param expires(number) lifetime in SHM (ttl) is calculated from this
-- @param data (string)
-- @param hash (string)
-- @return encoded cookie-string value
function shm:save(id, expires, data, hash, close)
    local lifetime = expires - now()
    if lifetime > 0 then
        local key = self:key(id)
        local ok, err = self.store:set(key, data, lifetime)
        if self.uselocking and close then
            self.lock:unlock()
        end
        if ok then
            return concat({ key, expires, self.encode(hash) }, self.delimiter)
        end
        return nil, err
    end
    if self.uselocking and close then
        self.lock:unlock()
    end
    return nil, "expired"
end

-- release any locks
-- @return true
function shm:close()
    if self.uselocking then
        self.lock:unlock()
    end
    return true
end

-- destroy the session by deleting is from the SHM
-- @param id (string) id of session to destroy
-- @return true
function shm:destroy(id)
    self.store:delete(self:key(id))
    if self.uselocking then
        self.lock:unlock()
    end
    return true, nil
end

-- updates the remaining ttl in the SHM
-- @param id (string) id of session to update
-- @param lifetime (number) time in seconds the value should remain available
function shm:ttl(id, lifetime)
  local k = self:key(id)
  return self.store:expire(k, lifetime)
end

return shm
