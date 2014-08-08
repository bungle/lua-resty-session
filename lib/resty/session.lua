local base64enc  = ngx.encode_base64
local base64dec  = ngx.decode_base64
local ngx_var    = ngx.var
local hmac       = ngx.hmac_sha1
local time       = ngx.time
local type       = type
local json       = require "cjson"
local aes        = require "resty.aes"
local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local ffi_typeof = ffi.typeof
local C          = ffi.C

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
    return base64enc(value):gsub("[+/=]", ENCODE_CHARS)
end

local function decode(value)
    return base64dec(value:gsub("[-_.]", DECODE_CHARS))
end

function setcookie(session, v, e)
    if e then
        e = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT"
    else
        e = ""
    end
    local d = session.cookie.domain
    if d == "localhost" then
        d = ""
    else
        d = "; Domain=" .. d
    end
    local s = ""
    if session.cookie.secure then
        s = "; Secure"
    end
    local h = ""
    if session.cookie.httponly then
        h = "; HttpOnly"
    end
    local p = "; Path=" .. (session.cookie.path or "/")
    local k = session.name .. "="
    local cookies = ngx.header["Set-Cookie"]
    local t = type(cookies)
    if t == "table" then
        local found = false
        for i, cookie in ipairs(cookies) do
            if cookie:find(k, 1, true) then
                cookies[i] = k .. v .. e .. d .. p .. s .. h
                found = true
                break
            end
        end
        if not found then
            cookies[#cookies + 1] = k .. v .. e .. d .. p .. s .. h
        end
    elseif t == "string" then
        if cookies:find(k, 1, true) then
            cookies = k .. v .. e .. d .. p .. s .. h
        else
            cookies = { cookies, k .. v .. e .. d .. p .. s .. h }
        end
    else
        cookies = k .. v .. e .. d .. p .. s .. h
    end
    ngx.header["Set-Cookie"] = cookies
    return true
end

local function getcookie(c)
    if c == nil then return nil end
    local r = {}
    local p, s, e = 1, c:find("|", 1, true)
    while s do
        r[#r + 1] = c:sub(p, e - 1)
        p = e + 1
        s, e = c:find("|", p, true)
    end
    r[#r + 1] = c:sub(p)
    if #r ~= 4 then return nil end
    return decode(r[1]), tonumber(r[2]), decode(r[3]), decode(r[4])
end

local config

do
    local sn = ngx_var.session_name                      or "session"
    local sr = ngx_var.session_cookie_renew              or 600
    local sl = ngx_var.session_cookie_lifetime           or 3600
    local sp = ngx_var.session_cookie_path               or "/"
    local sd = ngx_var.session_cookie_domain
    local ss = enabled(ngx_var.session_cookie_secure)
    local sh = enabled(ngx_var.session_cookie_httponly   or true)
    local su = enabled(ngx_var.session_check_ua          or true)
    local sc = enabled(ngx_var.session_check_scheme      or true)
    local sa = enabled(ngx_var.session_check_addr        or false)
    local cm = CIPHER_MODES[ngx_var.session_cipher_mode] or "cbc"
    local cs = CIPHER_SIZES[ngx_var.session_cipher_size] or 256
    local ch = aes.hash[ngx_var.session_cipher_hash]     or aes.hash.sha512
    local cr = ngx_var.session_cipher_rounds             or 1
    local sk = ngx_var.session_secret                    or random(cs / 8)
    local iz = ngx_var.session_identifier_length         or 16

    if type(sr) ~= "number" then sr = tonumber(sr) or 600  end
    if type(sl) ~= "number" then sl = tonumber(sl) or 3600 end
    if type(cr) ~= "number" then cr = tonumber(cr) or 1    end
    if type(iz) ~= "number" then iz = tonumber(iz) or 16   end

    config = { name = sn, secret = sk, cookie = {
        renew     = sr,
        lifetime  = sl,
        path      = sp,
        domain    = sd,
        secure    = ss,
        httponly  = sh
    },  cipher    = {
          size    = cs,
          mode    = cm,
          hash    = ch,
          rounds  = cr
    }, identifier = {
          length  = iz
    }}
end

local session = {}
session.__index = session

function session.start(opts)
    local self = setmetatable(opts or {}, session)
    if not self.name   then self.name   = config.name   end
    if not self.secret then self.secret = config.secret end
    if not self.cookie then
        self.cookie = {
            renew    = config.cookie.renew,
            lifetime = config.cookie.lifetime,
            path     = config.cookie.path,
            domain   = config.cookie.domain,
            secure   = config.cookie.secure,
            httponly = config.cookie.httponly
        }
    else
        if not self.cookie.renew    then self.cookie.renew    = config.cookie.renew    end
        if not self.cookie.lifetime then self.cookie.lifetime = config.cookie.lifetime end
        if not self.cookie.path     then self.cookie.path     = config.cookie.path     end
        if not self.cookie.domain   then self.cookie.domain   = config.cookie.domain   end
        if not self.cookie.secure   then self.cookie.secure   = config.cookie.secure   end
        if not self.cookie.httponly then self.cookie.httponly = config.cookie.httponly end
    end
    if not self.cipher then
        self.cipher = {
            size   = config.cipher.size,
            mode   = config.cipher.mode,
            hash   = config.cipher.hash,
            rounds = config.cipher.rounds
        }
    else
        if not self.cipher.size   then self.cipher.size   = config.cipher.size   end
        if not self.cipher.mode   then self.cipher.mode   = config.cipher.mode   end
        if not self.cipher.hash   then self.cipher.hash   = config.cipher.hash   end
        if not self.cipher.rounds then self.cipher.rounds = config.cipher.rounds end
    end
    if not self.identifier then
        self.identifier = { length = config.identifier.length }
    else
        if not self.identifier.length then self.identifier.length = config.identifier.length end
    end
    local si = ngx_var.ssl_session_id
    if self.cookie.secure == nil then
        if si then
            self.cookie.secure = true
        else
            self.cookie.secure = false
        end
    end
    if self.cookie.domain == nil then
        self.cookie.domain = ngx_var.host
    end
    self.key = ""
    if si then self.key = self.key .. si end
    if su then self.key = self.key .. ngx_var.http_user_agent end
    if sa then self.key = self.key .. ngx_var.remote_addr end
    if sc then self.key = self.key .. ngx_var.scheme end
    if self.cookie.httponly == nil then
        self.cookie.httponly = true
    end
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