local base64enc   = ngx.encode_base64
local base64dec   = ngx.decode_base64
local ngx_var     = ngx.var
local concat      = table.concat
local hmac        = ngx.hmac_sha1
local time        = ngx.time
local cookie_time = ngx.cookie_time
local type        = type
local json        = require "cjson"
local aes         = require "resty.aes"
local ffi         = require "ffi"
local ffi_cdef    = ffi.cdef
local ffi_new     = ffi.new
local ffi_str     = ffi.string
local ffi_typeof  = ffi.typeof
local C           = ffi.C

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

local CIPHER_MODES = {
    ecb    = "ecb",
    cbc    = "cbc",
    cfb1   = "cfb1",
    cfb8   = "cfb8",
    cfb128 = "cfb128",
    ofb    = "ofb",
    ctr    = "ctr"
}

local CIPHER_SIZES = {
    ["128"] = 128,
    ["192"] = 192,
    ["256"] = 256
}

ffi_cdef[[
typedef unsigned char u_char;
int RAND_pseudo_bytes(u_char *buf, int num);
]]

local t = ffi_typeof("uint8_t[?]")

local function random(len)
    local s = ffi_new(t, len)
    C.RAND_pseudo_bytes(s, len)
    return ffi_str(s, len)
end

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local function encode(value)
    return (base64enc(value):gsub("[+/=]", ENCODE_CHARS))
end

local function decode(value)
    return base64dec((value:gsub("[-_.]", DECODE_CHARS)))
end

function setcookie(session, value, expires)
    local cookie = { session.name, "=", value }
    local domain = session.cookie.domain
    if expires then
        cookie[#cookie + 1] = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"
    elseif session.cookie.persistent then
        cookie[#cookie + 1] = "; Expires="
        cookie[#cookie + 1] = cookie_time(session.expires)
    end
    if domain ~= "localhost" then
        cookie[#cookie + 1] = "; Domain="
        cookie[#cookie + 1] = domain
    end
    cookie[#cookie + 1] = "; Path="
    cookie[#cookie + 1] = session.cookie.path or "/"
    if session.cookie.secure then
        cookie[#cookie + 1] = "; Secure"
    end
    if session.cookie.httponly then
        cookie[#cookie + 1] = "; HttpOnly"
    end
    local needle = concat(cookie, nil, 1, 2)
    cookie = concat(cookie)
    local cookies = ngx.header["Set-Cookie"]
    local t = type(cookies)
    if t == "table" then
        local found = false
        for i, cookie in ipairs(cookies) do
            if cookie:find(needle, 1, true) == 1 then
                cookies[i] = cookie
                found = true
                break
            end
        end
        if not found then
            cookies[#cookies + 1] = cookie
        end
    elseif t == "string" and cookies:find(needle, 1, true) ~= 1  then
        cookies = { cookies, cookie }
    else
        cookies = cookie
    end
    ngx.header["Set-Cookie"] = cookies
    return true
end

local function getcookie(cookie)
    if not cookie then return end
    local r = {}
    local i, p, s, e = 1, 1, cookie:find("|", 1, true)
    while s do
        if i > 3 then return end
        r[i] = cookie:sub(p, e - 1)
        i, p = i + 1, e + 1
        s, e = cookie:find("|", p, true)
    end
    r[4] = cookie:sub(p)
    return decode(r[1]), tonumber(r[2]), decode(r[3]), decode(r[4])
end

local session = {
    _VERSION = "1.1",
    name = ngx_var.session_name or "session",
    cookie = {
        persistent = enabled(ngx_var.session_cookie_persistent or false),
        renew      = tonumber(ngx_var.session_cookie_renew)    or 600,
        lifetime   = tonumber(ngx_var.session_cookie_lifetime) or 3600,
        path       = ngx_var.session_cookie_path               or "/",
        domain     = ngx_var.session_cookie_domain,
        secure     = enabled(ngx_var.session_cookie_secure),
        httponly   = enabled(ngx_var.session_cookie_httponly   or true)
    }, check = {
        ssi    = enabled(ngx_var.session_check_ssi    or true),
        ua     = enabled(ngx_var.session_check_ua     or true),
        scheme = enabled(ngx_var.session_check_scheme or true),
        addr   = enabled(ngx_var.session_check_addr   or false)
    }, cipher = {
        size   = CIPHER_SIZES[ngx_var.session_cipher_size] or 256,
        mode   = CIPHER_MODES[ngx_var.session_cipher_mode] or "cbc",
        hash   = aes.hash[ngx_var.session_cipher_hash]     or aes.hash.sha512,
        rounds = tonumber(ngx_var.session_cipher_rounds)   or 1
    }, identifier = {
        length  = tonumber(ngx_var.session_identifier_length) or 16
}}

session.secret = ngx_var.session_secret or random(session.cipher.size / 8)
session.__index = session

function session.start(opts)
    local self = setmetatable(opts or {}, session)
    local ssi = ngx_var.ssl_session_id
    if self.cookie.secure == nil then
        if ssi then
            self.cookie.secure = true
        else
            self.cookie.secure = false
        end
    end
    if self.cookie.domain == nil then
        self.cookie.domain = ngx_var.host
    end
    self.key = concat{
        self.check.ssi    and ssi                     or "",
        self.check.ua     and ngx_var.http_user_agent or "",
        self.check.addr   and ngx_var.remote_addr     or "",
        self.check.scheme and ngx_var.scheme          or ""
    }
    local now, i, e, d, h = time(), getcookie(ngx.var["cookie_" .. self.name])
    if i and e and e > now then
        self.id = i
        self.expires = e
        local k = hmac(self.secret, self.id .. self.expires)
        local a = aes:new(k, self.id, aes.cipher(self.cipher.size, self.cipher.mode), self.cipher.hash, self.cipher.rounds)
        d = a:decrypt(d)
        if d and hmac(k, self.id .. self.expires .. d .. self.key) == h then
            local data = json.decode(d)
            if type(data) == "table" then
                self.data = data
                if self.expires - now < self.cookie.renew then
                    self:save()
                end
                return self
            end
        end
    end
    if type(self.data) ~= "table" then self.data = {} end
    self:regenerate()
    return self
end

function session:regenerate(flush)
    self.id = random(self.identifier.length)
    if flush then self.data = {} end
    return self:save()
end

function session:save()
    self.expires = time() + self.cookie.lifetime
    local k = hmac(self.secret, self.id .. self.expires)
    local d = json.encode(self.data)
    local h = hmac(k, self.id .. self.expires .. d .. self.key)
    local a = aes:new(k, self.id, aes.cipher(self.cipher.size, self.cipher.mode), self.cipher.hash, self.cipher.rounds)
    return setcookie(self, encode(self.id) .. "|" .. self.expires .. "|" .. encode(a:encrypt(d)) .. "|" .. encode(h))
end

function session:destroy()
    self.data = {}
    return setcookie(self, "", true)
end

return session