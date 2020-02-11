local require      = require
local var          = ngx.var
local header       = ngx.header
local concat       = table.concat
local ngx          = ngx
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

-- convert option to boolean
-- @param val input
-- @return `true` on `true`, "1", "on" or "true", or `nil` on `nil`, or `false` otherwise
local function enabled(val)
    if val == nil then return nil end
    return val == true or (val == "1" or val == "true" or val == "on")
end

-- returns the input value, or the default if the input is nil
local function ifnil(value, default)
    if value == nil then
        return default
    end
    return enabled(value)
end

-- loads a module if it exists, or alternatively a default module
-- @param prefix (string) a prefix for the module name to load, eg. "resty.session.encoders."
-- @param package (string) name of the module to load
-- @param default (string) the default module name, if `package` doesn't exist
-- @return the module table, and the name of the module loaded (either package, or default)
local function prequire(prefix, package, default)
    local o, p = pcall(require, prefix .. package)
    if not o then
        return require(prefix .. default), default
    end
    return p, package
end


-- create and set a cookie-header.
-- @session_obj (table) the session object for which to create the cookie
-- @value value (string) the string value to set (must be encoded already). Defaults to an empty string.
-- @value expires (boolean) if thruthy, the created cookie will delete the existing session-data.
-- @return true
local function setcookie(session_obj, value, expires)
    if ngx.headers_sent then return nil, "Attempt to set session cookie after sending out response headers." end
    value = value or ""
    local cookie_obj = session_obj.cookie
    local i = 3
    local k = {}
    local cookie_domain = cookie_obj.domain
    local cookie_samesite = cookie_obj.samesite

    -- build cookie parameters, elements 1+2 will be set later
    if expires then
        -- we're expiring/deleting the data, so set an expiry in the past
        k[i] = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"
        i=i+1
    elseif cookie_obj.persistent then
        k[i]   = "; Expires="
        k[i+1] = http_time(session_obj.expires)
        k[i+2] = "; Max-Age="
        k[i+3] = cookie_obj.lifetime
        i=i+4
    end
    if cookie_domain and cookie_domain ~= "localhost" and cookie_domain ~= "" then
        k[i]   = "; Domain="
        k[i+1] = cookie_domain
        i=i+2
    end
    k[i]   = "; Path="
    k[i+1] = cookie_obj.path or "/"
    i=i+2
    if cookie_samesite == "Lax" or cookie_samesite == "Strict" or cookie_samesite == "None" then
        k[i] = "; SameSite="
        k[i+1] = cookie_samesite
        i=i+2
    end
    if cookie_obj.secure then
        k[i] = "; Secure"
        i=i+1
    end
    if cookie_obj.httponly then
        k[i] = "; HttpOnly"
    end

    -- How many chunks do we need?
    local l
    if expires and cookie_obj.chunks then
        -- expiring cookie, so deleting data. Do not measure data, but use
        -- existing chunk count to make sure we clear all of them
        l = cookie_obj.chunks
    else
        -- calculate required chunks from data
        l = max(ceil(#value / cookie_obj.maxsize), 1)
    end

    local cookie_header = header["Set-Cookie"]
    for j=1, l do
        -- create numbered chunk names if required
        local chunk_name = { session_obj.name }
        if j > 1 then
            chunk_name[2] = "_"
            chunk_name[3] = j
            chunk_name[4] = "="
        else
            chunk_name[2] = "="
        end
        chunk_name = concat(chunk_name)
        k[1] = chunk_name

        if expires then
            -- expiring cookie, so deleting data; clear it
            k[2] = ""
        else
            -- grab the piece for the current chunk
            local sp = j * cookie_obj.maxsize - (cookie_obj.maxsize - 1)
            if j < l then
                k[2] = sub(value, sp, sp + (cookie_obj.maxsize - 1)) .. "0"
            else
                k[2] = sub(value, sp)
            end
        end

        -- build header value and add it to the header table/string
        -- replace existing chunk-name, or append
        local y = concat(k)
        local t = type(cookie_header)
        if t == "table" then
            local f = false
            local z = #cookie_header
            for a=1, z do
                if find(cookie_header[a], chunk_name, 1, true) == 1 then
                    cookie_header[a] = y
                    f = true
                    break
                end
            end
            if not f then
                cookie_header[z+1] = y
            end
        elseif t == "string" and find(cookie_header, chunk_name, 1, true) ~= 1  then
            cookie_header = { cookie_header, y }
        else
            cookie_header = y
        end
    end
    header["Set-Cookie"] = cookie_header
    return true
end

-- read the cookie for the session object.
-- @param session_obj (table) the session object for which to read the cookie
-- @param i (number) do not use! internal recursion variable
-- @return string with cookie data (and the property `session.cookie.chunks`
--         will be set to the actual number of chunks read)
local function getcookie(session_obj, i)
    local name = session_obj.name
    local n = { "cookie_", name }
    if i then
        n[3] = "_"
        n[4] = i
    else
        i = 1
    end
    session_obj.cookie.chunks = i
    local chunk_data = var[concat(n)]
    if not chunk_data then return nil end
    local l = #chunk_data
    if l <= session_obj.cookie.maxsize then return chunk_data end
    return concat{ sub(chunk_data, 1, session_obj.cookie.maxsize), getcookie(session_obj, i + 1) or "" }
end


-- save the session.
-- This will write to storage, and set the cookie (if returned by storage).
-- @param session (table) the session object
-- @param close (boolean) wether or not to close the "storage state" (unlocking locks etc)
-- @return true on success
local function save(session, close)
    session.expires = time() + session.cookie.lifetime
    local cookie, err = session.strategy.save(session, close)
    if cookie then
        return setcookie(session, cookie)
    end
    return nil, err
end

-- regenerates the session. Generates a new session ID.
-- @param session (table) the session object
-- @param flush (boolean) if thruthy the old session will be destroyed, and data deleted
-- @return nothing
local function regenerate(session, flush)
    local old_id = session.present and session.id
    session.id = session:identifier()
    if flush then
        if old_id and session.storage.destroy then
            session.storage:destroy(old_id)
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
            delimiter  = var.session_cookie_delimiter          or "|",
            maxsize    = var.session_cookie_maxsize            or 4000
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
    _VERSION = "2.26"
}

session.__index = session


-- Constructor: creates a new session
-- @return new session object
function session.new(opts)
    if getmetatable(opts) == session then
        return opts
    end
    if not defaults then
        init()
    end
    opts = type(opts) == "table" and opts or defaults
    local cookie_opts, cookie_defaults = opts.cookie or defaults.cookie, defaults.cookie
    local check_opts,  check_defaults = opts.check  or defaults.check,  defaults.check
    local ident_mod,  ident_name  = prequire("resty.session.identifiers.",
                                             opts.identifier or defaults.identifier, "random")
    local serial_mod, serial_name = prequire("resty.session.serializers.",
                                             opts.serializer or defaults.serializer, "json")
    local enc_mod,    enc_name    = prequire("resty.session.encoders.",
                                             opts.encoder or defaults.encoder, "base64")
    local ciph_mod,   ciph_name   = prequire("resty.session.ciphers.",
                                             opts.cipher or defaults.cipher, "aes")
    local stor_mod,   stor_name   = prequire("resty.session.storage.",
                                             opts.storage or defaults.storage, "cookie")
    local strat_mod,  strat_name  = prequire("resty.session.strategies.",
                                             opts.strategy or defaults.strategy, "default")
    local hmac_mod,   hmac_name   = prequire("resty.session.hmac.",
                                             opts.hmac or defaults.hmac, "sha1")
    local self = {
        name       = opts.name   or defaults.name,
        identifier = ident_mod,
        serializer = serial_mod,
        strategy   = strat_mod,
        encoder    = enc_mod,
        hmac       = hmac_mod,
        data       = opts.data   or {},
        secret     = opts.secret or defaults.secret,
        cookie = {
            persistent = ifnil(cookie_opts.persistent, cookie_defaults.persistent),
            discard    = cookie_opts.discard        or cookie_defaults.discard,
            renew      = cookie_opts.renew          or cookie_defaults.renew,
            lifetime   = cookie_opts.lifetime       or cookie_defaults.lifetime,
            path       = cookie_opts.path           or cookie_defaults.path,
            domain     = cookie_opts.domain         or cookie_defaults.domain,
            samesite   = cookie_opts.samesite       or cookie_defaults.samesite,
            secure     = ifnil(cookie_opts.secure,     cookie_defaults.secure),
            httponly   = ifnil(cookie_opts.httponly,   cookie_defaults.httponly),
            delimiter  = cookie_opts.delimiter      or cookie_defaults.delimiter,
            maxsize    = cookie_opts.maxsize        or cookie_defaults.maxsize
        }, check = {
            ssi        = ifnil(check_opts.ssi,        check_defaults.ssi),
            ua         = ifnil(check_opts.ua,         check_defaults.ua),
            scheme     = ifnil(check_opts.scheme,     check_defaults.scheme),
            addr       = ifnil(check_opts.addr,       check_defaults.addr)
        }
    }
    if opts[ident_name]  and not self[ident_name]  then self[ident_name]  = opts[ident_name] end
    if opts[serial_name] and not self[serial_name] then self[serial_name] = opts[serial_name] end
    if opts[enc_name]    and not self[enc_name]    then self[enc_name]    = opts[enc_name] end
    if opts[ciph_name]   and not self[ciph_name]   then self[ciph_name]   = opts[ciph_name] end
    if opts[stor_name]   and not self[stor_name]   then self[stor_name]   = opts[stor_name] end
    if opts[strat_name]  and not self[strat_name]  then self[strat_name]  = opts[strat_name] end
    if opts[hmac_name]   and not self[hmac_name]   then self[hmac_name]   = opts[hmac_name] end
    self.cipher  = ciph_mod.new(self)
    self.storage = stor_mod.new(self)
    return setmetatable(self, session)
end

-- Constructor: creates a new session, opening the current session
-- @return 1) new session object, 2) true if session was present
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

-- Constructor: creates a new session, opening the current session, and
-- renews/saves the session to storage if needed.
-- @return 1) new session object, 2) true if session was present
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

-- regenerates the session. Generates a new session ID and saves it.
-- @param self (table) the session object
-- @param flush (boolean) if thruthy the old session will be destroyed, and data deleted
-- @return nothing
function session:regenerate(flush)
    regenerate(self, flush)
    return save(self)
end

-- save the session.
-- This will write to storage, and set the cookie (if returned by storage).
-- @param session (table) the session object
-- @param close (boolean, defaults to true) wether or not to close the "storage state" (unlocking locks etc)
-- @return true on success
function session:save(close)
    if not self.id then
        self.id = self:identifier()
    end
    return save(self, close ~= false)
end

-- Destroy the session, clear data.
-- Note: will write the new (empty) cookie
-- @return true
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

-- closes the "storage state" (unlocking locks etc)
-- @return true
function session:close()
    local id = self.present and self.id
    if id and self.storage.close then
        return self.storage:close(id)
    end

    self.closed = true
    return true
end

-- Hide the current incoming session cookie by removing it from the "Cookie"
-- header, whilst leaving other cookies in there.
-- @return nothing
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
            local key = gsub(sub(c, 1, b - 1), "^%s+", "") -- strip leading whitespace
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
