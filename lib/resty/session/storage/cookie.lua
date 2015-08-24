local utils        = require "resty.session.utils"
local split        = utils.split
local decode       = utils.decode
local encode       = utils.encode
local concat       = table.concat
local tonumber     = tonumber
local setmetatable = setmetatable

local cookie = {}

cookie.__index = cookie

function cookie.new()
    return setmetatable({}, cookie)
end

function cookie:open(cookie)
    local r = split(cookie, "|", 4)
    if r and r[1] and r[2] and r[3] and r[4] then
        return decode(r[1]), tonumber(r[2]), decode(r[3]), decode(r[4])
    end
    return nil, "invalid"
end

function cookie:save(i, e, d, h)
    return concat({ encode(i), e, encode(d), encode(h) }, "|")
end

return cookie