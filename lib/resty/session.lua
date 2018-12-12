local require      = require
local var          = ngx.var
local header       = ngx.header
local concat       = table.concat
local time         = ngx.time
local http_time    = ngx.http_time
local set_header   = ngx.req.set_header
local clear_header = ngx.req.clear_header
local ceil         = math.ceil
local max          = math.max
local find         = string.find
local gsub         = string.gsub
local sub          = string.sub
local type         = type
local pcall        = pcall
local tonumber     = tonumber
local setmetatable = setmetatable
local getmetatable = getmetatable
local random       = require "resty.random".bytes

local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

local function ifnil(value, default)
    if value == nil then
        return default
    end
    return enabled(value)
end

local function prequire(prefix, package, default)
    local o, p = pcall(require, prefix .. package)
    if not o then
        return require(prefix .. default), default
    end
    return p, package
end

local function setcookie(session, value, expires)
    if ngx.headers_sent then return nil, "Attempt to set session cookie after sending out response headers." end
    local c = session.cookie
    local i = 3
    local k = {}
    local d = c.domain
    local x = c.samesite
    if expires then
        k[i] = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"
        i=i+1
    elseif c.persistent then
        k[i]   = "; Expires="
        k[i+1] = http_time(session.expires)
        k[i+2] = "; Max-Age="
        k[i+3] = c.lifetime
        i=i+4
    end
    if d and d ~= "localhost" and d ~= "" then
        k[i]   = "; Domain="
        k[i+1] = d
        i=i+2
    end
    k[i]   = "; Path="
    k[i+1] = c.path or "/"
    i=i+2
    if x == "Lax" or x == "Strict" then
        k[i] = "; SameSite="
        k[i+1] = x
        i=i+2
    end
    if c.secure then
        k[i] = "; Secure"
        i=i+1
    end
    if c.httponly then
        k[i] = "; HttpOnly"
    end
    local v = value or ""
    local l
    if expires and c.chunks then
        l = c.chunks
    else
        l = max(ceil(#v / 4000), 1)
    end
    local s = header["Set-Cookie"]
    for j=1, l do
        local n = { session.name }
        if j > 1 then
            n[2] = "_"
            n[3] = j
            n[4] = "="
        else
            n[2] = "="
        end
        n = concat(n)
        k[1] = n
        if expires then
            k[2] = ""
        else
            local sp = j * 4000 - 3999
            if j < l then
                k[2] = sub(v, sp, sp + 3999) .. "0"
            else
                k[2] = sub(v, sp)
            end
        end
        local y = concat(k)
        local t = type(s)
        if t == "table" then
            local f = false
            local z = #s
            for a=1, z do
                if find(s[a], n, 1, true) == 1 then
                    s[a] = y
                    f = true
                    break
                end
            end
            if not f then
                s[z+1] = y
            end
        elseif t == "string" and find(s, n, 1, true) ~= 1  then
            s = { s, y }
        else
            s = y
        end
    end
    header["Set-Cookie"] = s
    return true
end

local function getcookie(session, i)
    local name = session.name
    local n = { "cookie_", name }
    if i then
        n[3] = "_"
        n[4] = i
    else
        i = 1
    end
    session.cookie.chunks = i
    local c = var[concat(n)]
    if not c then return nil end
    local l = #c
    if l < 4001 then return c end
    return concat{ sub(c, 1, 4000), getcookie(session, i + 1) or "" }
end

local function save(session, close)
    session.expires = time() + session.cookie.lifetime
    local cookie, err = session.strategy.save(session, close)
    if cookie then
        return setcookie(session, cookie)
    end
    return nil, err
end

local function regenerate(session, flush)
    local i = session.present and session.id
    session.id = session:identifier()
    if flush then
        if i and session.storage.destroy then
            session.storage:destroy(i)
        end
        session.data = {}
    end
end

local secret = random(32, true) or random(32)
local defaults

local function init()
    defaults = {
        name       = var.session_name       or "session",
        identifier = var.session_identifier or "random",
        strategy   = var.session_strategy   or "default",
        storage    = var.session_storage    or "cookie",
        serializer = var.session_serializer or "json",
        encoder    = var.session_encoder    or "base64",
        cipher     = var.session_cipher     or "aes",
        hmac       = var.session_hmac       or "sha1",
        cookie = {
            persistent = enabled(var.session_cookie_persistent or false),
            discard    = tonumber(var.session_cookie_discard)  or 10,
            renew      = tonumber(var.session_cookie_renew)    or 600,
            lifetime   = tonumber(var.session_cookie_lifetime) or 3600,
            path       = var.session_cookie_path               or "/",
            domain     = var.session_cookie_domain,
            samesite   = var.session_cookie_samesite           or "Lax",
            secure     = enabled(var.session_cookie_secure),
            httponly   = enabled(var.session_cookie_httponly   or true),
            delimiter  = var.session_cookie_delimiter          or "|"
        }, check = {
            ssi    = enabled(var.session_check_ssi    or false),
            ua     = enabled(var.session_check_ua     or true),
            scheme = enabled(var.session_check_scheme or true),
            addr   = enabled(var.session_check_addr   or false)
        }
    }
    defaults.secret = var.session_secret or secret
end

local session = {
    _VERSION = "2.23"
}

session.__index = session

function session.new(opts)
    if getmetatable(opts) == session then
        return opts
    end
    if not defaults then
        init()
    end
    local z = defaults
    local y = type(opts) == "table" and opts or z
    local a, b = y.cookie or z.cookie, z.cookie
    local c, d = y.check  or z.check,  z.check
    local e, f = prequire("resty.session.identifiers.", y.identifier or z.identifier, "random")
    local g, h = prequire("resty.session.serializers.", y.serializer or z.serializer, "json")
    local i, j = prequire("resty.session.encoders.",    y.encoder    or z.encoder,    "base64")
    local k, l = prequire("resty.session.ciphers.",     y.cipher     or z.cipher,     "aes")
    local m, n = prequire("resty.session.storage.",     y.storage    or z.storage,    "cookie")
    local o, p = prequire("resty.session.strategies.",  y.strategy   or z.strategy,   "default")
    local q, r = prequire("resty.session.hmac.",        y.hmac       or z.hmac,       "sha1")
    local self = {
        name       = y.name   or z.name,
        identifier = e,
        serializer = g,
        strategy   = o,
        encoder    = i,
        hmac       = q,
        data       = y.data   or {},
        secret     = y.secret or z.secret,
        cookie = {
            persistent = ifnil(a.persistent, b.persistent),
            discard    = a.discard        or b.discard,
            renew      = a.renew          or b.renew,
            lifetime   = a.lifetime       or b.lifetime,
            path       = a.path           or b.path,
            domain     = a.domain         or b.domain,
            samesite   = a.samesite       or b.samesite,
            secure     = ifnil(a.secure,     b.secure),
            httponly   = ifnil(a.httponly,   b.httponly),
            delimiter  = a.delimiter      or b.delimiter
        }, check = {
            ssi        = ifnil(c.ssi,        d.ssi),
            ua         = ifnil(c.ua,         d.ua),
            scheme     = ifnil(c.scheme,     d.scheme),
            addr       = ifnil(c.addr,       d.addr)
        }
    }
    if y[f] and not self[f] then self[f] = y[f] end
    if y[h] and not self[h] then self[h] = y[h] end
    if y[j] and not self[j] then self[j] = y[j] end
    if y[l] and not self[l] then self[l] = y[l] end
    if y[n] and not self[n] then self[n] = y[n] end
    if y[p] and not self[p] then self[p] = y[p] end
    if y[r] and not self[r] then self[r] = y[r] end
    self.cipher  = k.new(self)
    self.storage = m.new(self)
    return setmetatable(self, session)
end

function session.open(opts)
    local self = opts
    if getmetatable(self) == session then
        if self.opened then
            return self, self.present
        end
    else
        self = session.new(opts)
    end

    if self.cookie.secure == nil then
        self.cookie.secure = var.scheme == "https" or var.https == "on"
    end

    self.key = concat{
        self.check.ssi    and var.ssl_session_id  or "",
        self.check.ua     and var.http_user_agent or "",
        self.check.addr   and var.remote_addr     or "",
        self.check.scheme and var.scheme          or "",
    }
    self.opened = true
    local cookie = getcookie(self)
    if cookie then
        if self.strategy.open(self, cookie) then
            return self, true
        end
    end
    regenerate(self, true)
    return self, false
end

function session.start(opts)
    if getmetatable(opts) == session and opts.started then
        return opts, opts.present
    end
    local self, present = session.open(opts)
    if present then
        if self.storage.start then
            local ok, err = self.storage:start(self.id)
            if not ok then return nil, err end
        end
        local now = time()
        if self.expires - now < self.cookie.renew or
           self.expires > now + self.cookie.lifetime then
            local ok, err = save(self)
            if not ok then return nil, err end
        end
    else
        local ok, err = save(self)
        if not ok then return nil, err end
    end
    self.started = true
    return self, present
end

function session:regenerate(flush)
    regenerate(self, flush)
    return save(self)
end

function session:save(close)
    if not self.id then
        self.id = self:identifier()
    end
    return save(self, close ~= false)
end

function session:destroy()
    if self.storage.destroy then
        self.storage:destroy(self.id)
    end
    self.data      = {}
    self.present   = nil
    self.opened    = nil
    self.started   = nil
    self.destroyed = true
    return setcookie(self, "", true)
end

function session:close()
    local i = session.present and session.id
    if i and self.storage.close then
        return session.storage:close()
    end

    self.closed = true
    return true
end

function session:hide()
    local cookies = var.http_cookie
    if not cookies then
        return
    end
    local r = {}
    local n = self.name
    local i = 1
    local j = 0
    local s = find(cookies, ";", 1, true)
    while s do
        local c = sub(cookies, i, s - 1)
        local b = find(c, "=", 1, true)
        if b then
            local key = gsub(sub(c, 1, b - 1), "^%s+", "")
            if key ~= n and key ~= "" then
                local z = #n
                if sub(key, z + 1, z + 1) ~= "_" or not tonumber(sub(key, z + 2)) then
                    j = j + 1
                    r[j] = c
                end
            end
        end
        i = s + 1
        s = find(cookies, ";", i, true)
    end
    local c = sub(cookies, i)
    if c and c ~= "" then
        local b = find(c, "=", 1, true)
        if b then
            local key = gsub(sub(c, 1, b - 1), "^%s+", "")
            if key ~= n and key ~= "" then
                local z = #n
                if sub(key, z + 1, z + 1) ~= "_" or not tonumber(sub(key, z + 2)) then
                    j = j + 1
                    r[j] = c
                end
            end
        end
    end
    if j == 0 then
        clear_header("Cookie")
    else
        set_header("Cookie", concat(r, "; ", 1, j))
    end
end

return session
