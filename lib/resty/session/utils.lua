local base64enc   = ngx.encode_base64
local base64dec   = ngx.decode_base64

local ENCODE_CHARS = {
    ["+"] = "-",
    ["/"] = "_",
    ["="] = "."
}

local DECODE_CHARS = {
    ["-"] = "+",
    ["_"] = "/",
    ["."] = "="
}

local utils = {}

function utils.encode(value)
    return (base64enc(value):gsub("[+/=]", ENCODE_CHARS))
end

function utils.decode(value)
    return base64dec((value:gsub("[-_.]", DECODE_CHARS)))
end

function utils.split(str, del, parts)
    local r = {}
    local i, p, z, s, e = 1, 1, parts - 1, str:find(del, 1, true)
    while s do
        if i > z then return end
        r[i] = str:sub(p, e - 1)
        i, p = i + 1, e + 1
        s, e = str:find(del, p, true)
    end
    if i ~= parts then
        return nil
    end
    r[parts] = str:sub(p)
    return r
end

return utils