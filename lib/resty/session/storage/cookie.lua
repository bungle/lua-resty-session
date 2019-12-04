local concat       = table.concat
local tonumber     = tonumber
local setmetatable = setmetatable

local cookie = {}

cookie.__index = cookie

function cookie.new(config)
    return setmetatable({
        encode    = config.encoder.encode,
        decode    = config.encoder.decode,
        delimiter = config.cookie.delimiter
    }, cookie)
end

-- Extracts the elements from the cookie-string (string-split essentially).
-- @param value (string) the string to split in the elements
-- @return array with the elements in order, or `nil` if the number of elements do not match expectations.
function cookie:cookie(value)
    local size = 5
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

-- returns 5 decoded data elements from the cookie-string
-- @param value (string) the cookie string containing the encoded data.
-- @return id (string), usebefore(number), expires(number), data (string), hash (string).
function cookie:open(value)
    local r = self:cookie(value)
    if r and r[1] and r[2] and r[3] and r[4] then
        return self.decode(r[1]), tonumber(r[2]), tonumber(r[3]), self.decode(r[4]), self.decode(r[5])
    end
    return nil, "invalid"
end

-- returns a cookie-string. Note that the cookie-storage does not store anything
-- server-side in this case.
-- @param id (string)
-- @param usebefore (number)
-- @param expires (number)
-- @param data (string)
-- @param hash (string)
-- @return encoded cookie-string value
function cookie:save(id, usebefore, expires, data, hash)
    return concat({ self.encode(id), tostring(usebefore), tostring(expires), self.encode(data), self.encode(hash) }, self.delimiter)
end

cookie.touch = cookie.save  -- identical in the 'cookie' case

return cookie
