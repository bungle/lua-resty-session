local require = require


local table_new = require "table.new"
local buffer = require "string.buffer"
local nkeys = require "table.nkeys"
local utils = require "resty.session.utils"
local bit = require "bit"


local setmetatable = setmetatable
local clear_header = ngx.req.clear_header
local set_header = ngx.req.set_header
local tonumber = tonumber
local assert = assert
local header = ngx.header
local error = error
local time = ngx.time
local band = bit.band
local byte = string.byte
local type = type
local sub = string.sub
local fmt = string.format
local bor = bit.bor
local var = ngx.var
local min = math.min


local derive_aes_gcm_256_key_and_iv = utils.derive_aes_gcm_256_key_and_iv
local derive_hmac_sha256_key = utils.derive_hmac_sha256_key
local encrypt_aes_256_gcm = utils.encrypt_aes_256_gcm
local decrypt_aes_256_gcm = utils.decrypt_aes_256_gcm
local encode_base64url = utils.encode_base64url
local decode_base64url = utils.decode_base64url
local encode_buffer = utils.encode_buffer
local decode_buffer = utils.encode_buffer
local load_storage = utils.load_storage
local encode_json = utils.encode_json
local decode_json = utils.decode_json
local base64_size = utils.base64_size
local hmac_sha256 = utils.hmac_sha256
local rand_bytes = utils.rand_bytes
local inflate = utils.inflate
local deflate = utils.deflate
local bunpack = utils.bunpack
local errmsg = utils.errmsg
local sha256 = utils.sha256
local bpack = utils.bpack
local trim = utils.trim


-- Type (1B) || Options (2B) || Session ID (32B) || Creation Time (8B) || Rolling Offset (4B) || Data Size (4B) || Tag (16B) || Idling Offset (2B) || Mac (6B) || [ Data (*B) ]


local COOKIE_TYPE_SIZE    = 1
local OPTIONS_SIZE        = 2
local SID_SIZE            = 32
local CREATED_AT_SIZE     = 8
local ROLLING_OFFSET_SIZE = 4
local DATA_SIZE           = 4
local TAG_SIZE            = 16
local IDLING_OFFSET_SIZE  = 2
local MAC_SIZE            = 6

local HEADER_SIZE = COOKIE_TYPE_SIZE + OPTIONS_SIZE + SID_SIZE + CREATED_AT_SIZE + ROLLING_OFFSET_SIZE +
                    DATA_SIZE + TAG_SIZE + IDLING_OFFSET_SIZE + MAC_SIZE
local HEADER_ENCODED_SIZE = base64_size(HEADER_SIZE)


local COMPRESSION_THRESHOLD = 1024 -- 1 kB
local COOKIE_TYPE           = bpack(COOKIE_TYPE_SIZE, 1)


local MAX_COOKIE_SIZE    = 4096
local MAX_COOKIES        = 9
local MAX_COOKIES_SIZE   = MAX_COOKIES * MAX_COOKIE_SIZE -- 36864 bytes
local MAX_IDLING_TIMEOUT = 65535


local OPTIONS_NONE         = 0x0000
local OPTION_STATELESS     = 0x0001
local OPTION_JSON          = 0x0010
local OPTION_STRING_BUFFER = 0x0020
local OPTION_DEFLATE       = 0x0100
local OPTIONS = {
  deflate           = OPTION_DEFLATE,
  json              = OPTION_JSON,
  ["string.buffer"] = OPTION_STRING_BUFFER,
}


local DEFAULT_AUDIENCE = ""
local DEFAULT_SUBJECT
local DEFAULT_META = {}
local DEFAULT_IKM
local DEFAULT_IKM_FALLBACKS


local DEFAULT_COOKIE_NAME = "session"
local DEFAULT_COOKIE_PATH = "/"
local DEFAULT_COOKIE_SAME_SITE = "Lax"
local DEFAULT_COOKIE_SAME_PARTY
local DEFAULT_COOKIE_PRIORITY
local DEFAULT_COOKIE_PARTITIONED
local DEFAULT_COOKIE_HTTP_ONLY = true
local DEFAULT_COOKIE_PREFIX
local DEFAULT_COOKIE_DOMAIN
local DEFAULT_COOKIE_SECURE


local DEFAULT_IDLING_TIMEOUT   = 900   -- 15 minutes
local DEFAULT_ROLLING_TIMEOUT  = 3600  -- 60 minutes
local DEFAULT_ABSOLUTE_TIMEOUT = 86400 -- 24 hours
local DEFAULT_STALE_TTL        = 10    -- 10 seconds


local DEFAULT_STORAGE


local STATE_NEW    = "new"
local STATE_OPEN   = "open"
local STATE_CLOSED = "closed"


local EQUALS_BYTE    = byte("=")
local SEMICOLON_BYTE = byte(";")


local COOKIE_EXPIRE_FLAGS = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"


local HEADER_BUFFER = buffer.new(HEADER_SIZE)
local FLAGS_BUFFER  = buffer.new(128)
local DATA_BUFFER   = buffer.new(MAX_COOKIES_SIZE)
local HIDE_BUFFER   = buffer.new(256)


local function calculate_mac(ikm, nonce, msg)
  local auth_key, err = derive_hmac_sha256_key(ikm, nonce)
  if not auth_key then
    return nil, errmsg(err, "unable to derive session message authentication key")
  end

  local mac, err = hmac_sha256(auth_key, msg)
  if not mac then
    return nil, errmsg(err, "unable to calculate session message authentication code")
  end

  return sub(mac, 1, MAC_SIZE)
end


local function calculate_cookie_chunks(cookie_name_size, data_size)
  local space_needed = cookie_name_size + 1 + HEADER_ENCODED_SIZE + data_size
  if space_needed > MAX_COOKIES_SIZE then
    return nil, "cookie size limit exceeded"
  end

  if space_needed <= MAX_COOKIE_SIZE then
    return 1
  end

  for i = 2, MAX_COOKIES do
    space_needed = space_needed + cookie_name_size + 2
    if space_needed > MAX_COOKIES_SIZE then
      return nil, "cookie size limit exceeded"
    elseif space_needed <= (MAX_COOKIE_SIZE * i) then
      return i
    end
  end

  return nil, "cookie size limit exceeded"
end


local function merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
  if not cookies then
    return cookie_data
  end

  if type(cookies) == "string" then
    if byte(cookies, cookie_name_size + 1) == EQUALS_BYTE and
       sub(cookies, 1, cookie_name_size) == cookie_name
    then
      return cookie_data
    end

    return { cookies, cookie_data }
  end

  if type(cookies) ~= "table" then
    return nil, "unable to merge session cookies with response cookies"
  end

  local count = #cookies
  for i = 1, count do
    if byte(cookies[i], cookie_name_size + 1) == EQUALS_BYTE and
       sub(cookies[i], 1, cookie_name_size) == cookie_name
    then
      cookies[i] = cookie_data
      return cookies
    end

    if i == count then
      cookies[i+1] = cookie_data
      return cookies
    end
  end
end


local function save(self, state)
  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name
  local options = self.options
  local stateless = band(options, OPTION_STATELESS) ~= 0

  local sid, err = rand_bytes(SID_SIZE)
  if not sid then
    return nil, errmsg(err, "unable to generate session id")
  end

  local meta = self.meta
  local current_time = time()
  local created_at = meta.created_at
  local rolling_offset
  if created_at then
    rolling_offset = current_time - created_at

  else
    created_at = current_time
    rolling_offset = 0
  end

  local data, data_size, cookie_chunks do
    local err
    if band(options, OPTION_STRING_BUFFER) ~= 0 then
      data, err = encode_buffer(self.data)

    else
      data, err = encode_json(self.data)
      if data then
        options = bor(options, OPTION_JSON)
      end
    end

    if not data then
      return nil, errmsg(err, "unable to encode session data")
    end

    data_size = #data

    if data_size > COMPRESSION_THRESHOLD then
      local deflated_data, err = deflate(data)
      if not deflated_data then
        -- TODO: log
      else
        if deflated_data then
          local deflated_size = #deflated_data
          if deflated_size < data_size then
            options = bor(options, OPTION_DEFLATE)
            data = deflated_data
            data_size = deflated_size
          end
        end
      end
    end

    data_size = base64_size(data_size)

    if stateless then
      cookie_chunks, err = calculate_cookie_chunks(cookie_name_size, data_size)
      if not cookie_chunks then
        return nil, err
      end

    else
      cookie_chunks = 1
    end
  end

  local idling_offset = 0

  local packed_options        = bpack(OPTIONS_SIZE, options)
  local packed_data_size      = bpack(DATA_SIZE, data_size)
  local packed_created_at     = bpack(CREATED_AT_SIZE, created_at)
  local packed_rolling_offset = bpack(ROLLING_OFFSET_SIZE, rolling_offset)
  local packed_idling_offset  = bpack(IDLING_OFFSET_SIZE, idling_offset)

  HEADER_BUFFER:reset()
  HEADER_BUFFER:put(COOKIE_TYPE, packed_options, sid, packed_created_at, packed_rolling_offset, packed_data_size)

  local ikm = self.ikm
  local key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid)
  if not key then
    return nil, errmsg(err, "unable to derive session encryption key")
  end

  local ciphertext, err, tag = encrypt_aes_256_gcm(key, iv, data, HEADER_BUFFER:tostring())
  if not ciphertext then
    return nil, errmsg(err, "unable to encrypt session data")
  end

  HEADER_BUFFER:put(tag, packed_idling_offset)

  local mac, err = calculate_mac(ikm, sid, HEADER_BUFFER:tostring())
  if not mac then
    return nil, err
  end

  local payload_header = HEADER_BUFFER:put(sub(mac, 1, MAC_SIZE)):get()
  payload_header, err = encode_base64url(payload_header)
  if not payload_header then
    return nil, errmsg(err, "unable to base64url encode session header")
  end

  local payload, err = encode_base64url(ciphertext)
  if not payload then
    return nil, errmsg(err, "unable to base64url encode session data")
  end

  local cookies = header["Set-Cookie"]
  local cookie_flags = self.cookie_flags

  local initial_chunk
  if cookie_chunks == 1 then
    local cookie_data
    if stateless then
      initial_chunk = payload
      cookie_data = fmt("%s=%s%s%s", cookie_name, payload_header, payload, cookie_flags)

    else
      cookie_data = fmt("%s=%s%s", cookie_name, payload_header, cookie_flags)
    end

    cookies, err = merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
    if not cookies then
      return nil, err
    end

  else
    DATA_BUFFER:set(payload)

    initial_chunk = DATA_BUFFER:get(MAX_COOKIE_SIZE - HEADER_ENCODED_SIZE - cookie_name_size - 1)

    local cookie_data = fmt("%s=%s%s%s", cookie_name, payload_header, initial_chunk, cookie_flags)
    cookies, err = merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
    if not cookies then
      return nil, err
    end

    for i = 2, cookie_chunks do
      local name = fmt("%s%d", cookie_name, i)
      cookie_data = DATA_BUFFER:get(MAX_COOKIE_SIZE - cookie_name_size - 2)
      cookie_data = fmt("%s=%s%s", name, cookie_data, cookie_flags)
      cookies, err = merge_cookies(cookies, cookie_name_size + 1, name, cookie_data)
      if not cookies then
        return nil, err
      end
    end
  end

  if stateless then
    local old_data_size = meta.data_size
    if old_data_size then
      local old_cookie_chunks = calculate_cookie_chunks(cookie_name_size, old_data_size)
      if old_cookie_chunks and old_cookie_chunks > cookie_chunks then
        for i = cookie_chunks + 1, old_cookie_chunks do
          local name = fmt("%s%d", cookie_name, i)
          local cookie_data = fmt("%s=%s%s", name, cookie_flags, COOKIE_EXPIRE_FLAGS)
          cookies, err = merge_cookies(cookies, cookie_name_size + 1, name, cookie_data)
          if not cookies then
            return nil, err
          end
        end
      end
    end

  else
    local key, err = encode_base64url(sid)
    if not key then
      return nil, errmsg(err, "unable to base64url encode session id")
    end

    local storage = self.storage
    local ok, err = storage:set(key, payload, self.rolling_timeout, current_time)
    if not ok then
      return nil, errmsg(err, "unable to store session data")
    end

    local old_sid = meta.sid
    if old_sid and storage.expire then
      key, err = encode_base64url(old_sid)
      if not key then
        -- TODO: log or ignore?

      else
        local stale_ttl = self.stale_ttl
        if storage.ttl then
          local ttl = storage:ttl(key)
          if ttl and ttl > stale_ttl then
            local ok, err = storage:expire(key, stale_ttl, current_time)
            if not ok then
              -- TODO: log or ignore?
            end
          end

        else
          ok, err = storage:expire(key, stale_ttl, current_time)
          if not ok then
            -- TODO: log or ignore?
          end
        end
      end
    end
  end

  header["Set-Cookie"] = cookies

  self.state = state or STATE_OPEN
  self.meta = {
    options        = options,
    sid            = sid,
    created_at     = created_at,
    rolling_offset = rolling_offset,
    data_size      = data_size,
    tag            = tag,
    idling_offset  = idling_offset,
    mac            = mac,
    ikm            = ikm,
    header         = header,
    initial_chunk  = initial_chunk,
  }

  return true
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value)
  assert(self.state ~= STATE_CLOSED, "unable to set session data on closed session")
  self.data[self.audience].data[key] = value
end


function metatable:get(key)
  assert(self.state ~= STATE_CLOSED, "unable to get session data on closed session")
  return self.data[self.audience].data[key]
end


function metatable:set_subject(subject)
  assert(self.state ~= STATE_CLOSED, "unable to set subject on closed session")
  self.data[self.audience].subject = subject
end


function metatable:get_subject()
  assert(self.state ~= STATE_CLOSED, "unable to get subject on closed session")
  return self.data[self.audience].subject
end


function metatable:set_audience(audience)
  assert(self.state ~= STATE_CLOSED, "unable to set audience on closed session")
  self.data[audience] = self.data[self.audience]
  self.data[self.audience] = nil
  self.audience = audience
end


function metatable:get_audience()
  assert(self.state ~= STATE_CLOSED, "unable to get audience on closed session")
  return self.audience
end


function metatable:get_sid()
  assert(self.state == STATE_OPEN, "unable to get session id on nonexistent or closed session")
  return self.meta.sid
end


function metatable:get_data_size()
  assert(self.state == STATE_OPEN, "unable to get session data size on nonexistent or closed session")
  return self.meta.data_size
end


function metatable:get_created_at()
  assert(self.state == STATE_OPEN, "unable to get session creation time on nonexistent or closed session")
  return self.meta.created_at
end


function metatable:get_rolling_offset()
  assert(self.state == STATE_OPEN, "unable to get session rolling offset on nonexistent or closed session")
  return self.meta.rolling_offset
end


function metatable:get_tag()
  assert(self.state == STATE_OPEN, "unable to get session tag on nonexistent or closed session")
  return self.meta.tag
end


function metatable:get_idling_offset()
  assert(self.state == STATE_OPEN, "unable to get session idling offset on nonexistent or closed session")
  return self.meta.idling_offset
end


function metatable:get_mac()
  assert(self.state == STATE_OPEN, "unable to get session mac on nonexistent or closed session")
  return self.meta.mac
end


function metatable:open(ngx_var)
  local current_time = time()
  local cookie_name = self.cookie_name
  local var = ngx_var or var
  local cookie = var["cookie_" .. cookie_name]
  if not cookie then
    return nil, "missing session cookie"
  end

  local header do
    header = sub(cookie, 1, HEADER_ENCODED_SIZE)
    if #header ~= HEADER_ENCODED_SIZE then
      return nil, "invalid session header"
    end
    local err
    header, err = decode_base64url(header)
    if not header then
      return nil, errmsg(err, "unable to base64url decode session header")
    end
  end

  HEADER_BUFFER:set(header)

  local cookie_type do
    cookie_type = HEADER_BUFFER:get(COOKIE_TYPE_SIZE)
    if #cookie_type ~= COOKIE_TYPE_SIZE then
      return nil, "invalid session cookie type"
    end
    if cookie_type ~= COOKIE_TYPE then
      return nil, "invalid session cookie type"
    end
  end

  local options, stateless do
    options = HEADER_BUFFER:get(OPTIONS_SIZE)
    if #options ~= OPTIONS_SIZE then
      return nil, "invalid session options"
    end

    options = bunpack(OPTIONS_SIZE, options)

    stateless = band(self.options, OPTION_STATELESS) ~= 0
    if stateless ~= (band(options, OPTION_STATELESS) ~= 0) then
      return nil, "invalid session options"
    end
  end

  local sid do
    sid = HEADER_BUFFER:get(SID_SIZE)
    if #sid ~= SID_SIZE then
      return nil, "invalid session id"
    end
  end

  local created_at do
    created_at = HEADER_BUFFER:get(CREATED_AT_SIZE)
    if #created_at ~= CREATED_AT_SIZE then
      return nil, "invalid session creation time"
    end

    created_at = bunpack(CREATED_AT_SIZE, created_at)

    local absolute_period = current_time - created_at
    local absolute_timeout = self.absolute_timeout
    if absolute_timeout ~= 0 then
      if absolute_period > absolute_timeout then
        return nil, "session absolute timeout exceeded"
      end
    end
  end

  local rolling_offset do
    rolling_offset = HEADER_BUFFER:get(ROLLING_OFFSET_SIZE)
    if #rolling_offset ~= ROLLING_OFFSET_SIZE then
      return nil, "invalid session rolling offset"
    end

    rolling_offset = bunpack(ROLLING_OFFSET_SIZE, rolling_offset)

    local rolling_timeout = self.rolling_timeout
    if rolling_timeout ~= 0 then
      local rolling_period = current_time - created_at - rolling_offset
      if rolling_period > rolling_timeout then
        return nil, "session rolling timeout exceeded"
      end
    end
  end

  local data_size do
    data_size = HEADER_BUFFER:get(DATA_SIZE)
    if #data_size ~= DATA_SIZE then
      return nil, "invalid session data size"
    end

    data_size = bunpack(DATA_SIZE, data_size)
  end

  local tag do
    tag = HEADER_BUFFER:get(TAG_SIZE)
    if #tag ~= TAG_SIZE then
      return nil, "invalid session tag"
    end
  end

  local idling_offset do
    idling_offset = HEADER_BUFFER:get(IDLING_OFFSET_SIZE)
    if #idling_offset ~= IDLING_OFFSET_SIZE then
      return nil, "invalid session idling offset"
    end

    idling_offset = bunpack(IDLING_OFFSET_SIZE, idling_offset)

    local idling_timeout = self.idling_timeout
    if idling_timeout ~= 0 then
      local idling_period = current_time - created_at - rolling_offset - idling_offset
      if idling_period > idling_timeout then
        return nil, "session idling timeout exceeded"
      end
    end
  end

  local mac, ikm do
    ikm = self.ikm
    mac = HEADER_BUFFER:get(MAC_SIZE)
    if #mac ~= MAC_SIZE then
      return nil, "invalid session message authentication code"
    end

    local msg = sub(header, 1, HEADER_SIZE - MAC_SIZE)
    local expected_mac, err = calculate_mac(ikm, sid, msg)
    if mac ~= expected_mac then
      local fallback_keys = self.ikm_fallbacks
      if fallback_keys then
        local count = #fallback_keys
        if count > 0 then
          for i = 1, count do
            ikm = fallback_keys[i]
            local expected_mac, err = calculate_mac(ikm, sid, msg)
            if mac == expected_mac then
              break
            end

            if i == count then
              return nil, errmsg(err, "invalid session message authentication code")
            end
          end

        else
          return nil, errmsg(err, "invalid session message authentication code")
        end

      else
        return nil, errmsg(err, "invalid session message authentication code")
      end
    end
  end

  local initial_chunk, ciphertext do
    if stateless then
      local cookie_chunks, err = calculate_cookie_chunks(#cookie_name, data_size)
      if not cookie_chunks then
        return nil, err
      end

      if cookie_chunks == 1 then
        initial_chunk = sub(cookie, -data_size)
        ciphertext = initial_chunk

      else
        initial_chunk = sub(cookie, HEADER_ENCODED_SIZE + 1)
        DATA_BUFFER:reset():put(initial_chunk)
        for i = 2, cookie_chunks do
          local chunk = var["cookie_" .. cookie_name .. i]
          if not chunk then
            return nil, errmsg(err, "missing session cookie chunk")
          end

          DATA_BUFFER:put(chunk)
        end

        ciphertext = DATA_BUFFER:get()
      end

    else
      local key, err = encode_base64url(sid)
      if not key then
        return nil, errmsg(err, "unable to base64url encode session id")
      end

      ciphertext, err = self.storage:get(key, current_time)
      if not ciphertext then
        return nil, errmsg(err, "unable to load session data")
      end
    end

    if #ciphertext ~= data_size then
      return nil, "invalid session payload"
    end

    local err
    ciphertext, err = decode_base64url(ciphertext)
    if not ciphertext then
      return nil, errmsg(err, "unable to base64url decode session data")
    end
  end

  local key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid)
  if not key then
    return nil, errmsg(err, "unable to derive session decryption key")
  end

  local aad = sub(header, 1, HEADER_SIZE - MAC_SIZE - TAG_SIZE - IDLING_OFFSET_SIZE)
  local plaintext, err = decrypt_aes_256_gcm(key, iv, ciphertext, aad, tag)
  if not plaintext then
    return nil, errmsg(err, "unable to decrypt session data")
  end

  local data do
    if band(options, OPTION_DEFLATE) ~= 0 then
      plaintext, err = inflate(plaintext)
      if not plaintext then
        return nil, errmsg(err, "unable to inflate session data")
      end
    end

    if band(options, OPTION_JSON) ~= 0 then
      data, err = decode_json(plaintext)
    elseif band(options, OPTION_STRING_BUFFER) ~= 0 then
      data, err = decode_buffer(plaintext)
    end

    if not data then
      return nil, errmsg(err, "unable to decode session data")
    end
  end

  self.meta = {
    options        = options,
    sid            = sid,
    created_at     = created_at,
    rolling_offset = rolling_offset,
    data_size      = data_size,
    tag            = tag,
    idling_offset  = idling_offset,
    mac            = mac,
    ikm            = ikm,
    header         = header,
    initial_chunk  = initial_chunk,
  }

  local audience = self.audience
  if not data[audience] then
    self.state = STATE_NEW
    data[audience] = self.data[audience]
    return nil, "missing session audience"
  end

  self.state = STATE_OPEN
  self.data = data

  return true
end


function metatable:save()
  return save(self)
end


function metatable:touch()
  assert(self.state == STATE_OPEN, "unable to touch nonexistent or closed session")

  local meta = self.meta
  local idling_offset = min(time() - meta.created_at - meta.rolling_offset, MAX_IDLING_TIMEOUT)

  HEADER_BUFFER:reset():put(sub(meta.header, 1, HEADER_SIZE - IDLING_OFFSET_SIZE - MAC_SIZE),
                            bpack(IDLING_OFFSET_SIZE, idling_offset))

  local mac, err = calculate_mac(meta.ikm, meta.sid, HEADER_BUFFER:tostring())
  if not mac then
    return nil, err
  end

  local payload_header = HEADER_BUFFER:put(mac):get()

  meta.idling_offset = idling_offset
  meta.mac           = mac
  meta.header        = payload_header

  payload_header, err = encode_base64url(payload_header)
  if not payload_header then
    return nil, errmsg(err, "unable to base64url encode session header")
  end

  local cookie_flags = self.cookie_flags
  local cookie_name = self.cookie_name
  local cookie_data
  if band(meta.options, OPTION_STATELESS) ~= 0 then
    cookie_data = fmt("%s=%s%s%s", cookie_name, payload_header, meta.initial_chunk, cookie_flags)
  else
    cookie_data = fmt("%s=%s%s", cookie_name, payload_header, cookie_flags)
  end

  header["Set-Cookie"] = merge_cookies(header["Set-Cookie"], #cookie_name, cookie_name, cookie_data)

  return true
end


function metatable:refresh()
  assert(self.state == STATE_OPEN, "unable to refresh nonexistent or closed session")

  local meta = self.meta
  local created_at = meta.created_at
  local rolling_offset = meta.rolling_offset

  local rolling_timeout = self.rolling_timeout
  if rolling_timeout == 0 then
    rolling_timeout = DEFAULT_ROLLING_TIMEOUT
  end

  local idling_timeout = self.idling_timeout
  if idling_timeout == 0 then
    idling_timeout = DEFAULT_IDLING_TIMEOUT
  end

  local time_to_rolling_expiry = rolling_timeout - (time() - created_at - rolling_offset)
  if time_to_rolling_expiry > idling_timeout then
    return self:touch()
  end

  return self:save()
end


function metatable:logout()
  assert(self.state == STATE_OPEN, "unable to logout nonexistent or closed session")

  local data = self.data
  if nkeys(data) == 1 then
    return self:destroy()
  end

  data[self.audience] = nil

  return save(self, STATE_CLOSED)
end


function metatable:destroy()
  assert(self.state == STATE_OPEN, "unable to destroy nonexistent or closed session")

  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local meta = self.meta
  local stateless = band(self.options, OPTION_STATELESS) ~= 0

  local cookie_chunks = 1
  local data_size = meta.data_size
  if stateless and data_size then
    local err
    cookie_chunks, err = calculate_cookie_chunks(cookie_name_size, data_size)
    if not cookie_chunks then
      return nil, err
    end
  end

  local cookie_flags = self.cookie_flags
  local cookie_data = fmt("%s=%s%s", cookie_name, cookie_flags, COOKIE_EXPIRE_FLAGS)
  local cookies, err = merge_cookies(header["Set-Cookie"], cookie_name_size, cookie_name, cookie_data)
  if not cookies then
    return nil, err
  end

  if cookie_chunks > 1 then
    for i = 2, cookie_chunks do
      local name = fmt("%s%d", cookie_name, i)
      cookie_data = fmt("%s=%s%s", name, cookie_flags, COOKIE_EXPIRE_FLAGS)
      cookies, err = merge_cookies(cookies, cookie_name_size + 1, name, cookie_data)
      if not cookies then
        return nil, err
      end
    end
  end

  if not stateless then
    local key, err = encode_base64url(meta.sid)
    if not key then
      return nil, errmsg(err, "unable to base64url encode session id")
    end

    local ok, err = self.storage:delete(key)
    if not ok then
      -- TODO: log or return nil, err?
    end
  end

  header["Set-Cookie"] = cookies

  self.state = STATE_CLOSED

  return true
end


function metatable:close()
  self.state = STATE_CLOSED
  return true
end


function metatable:hide(ngx_var)
  assert(self.state == STATE_OPEN, "unable to hide nonexistent session")

  local cookies = (ngx_var or var).http_cookie
  if not cookies or cookies == "" then
    return
  end

  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local stateless = band(self.options, OPTION_STATELESS) ~= 0

  local cookie_chunks
  if stateless then
    cookie_chunks = calculate_cookie_chunks(cookie_name_size, self.meta.data_size) or 1
  else
    cookie_chunks = 1
  end

  HIDE_BUFFER:reset()

  local size = #cookies
  local name
  local skip = false
  local start = 1
  for i = 1, size do
    local b = byte(cookies, i)
    if name then
      if b == SEMICOLON_BYTE or i == size then
        if not skip then
          local value
          if b == SEMICOLON_BYTE then
            value = trim(sub(cookies, start, i - 1))
          else
            value = trim(sub(cookies, start))
          end

          if value ~= "" then
            HIDE_BUFFER:put(value)
          end

          if i ~= size then
            HIDE_BUFFER:put("; ")
          end
        end

        if i == size then
          break
        end

        name = nil
        start = i + 1
        skip = false
      end

    else
      if b == EQUALS_BYTE or b == SEMICOLON_BYTE then
        name = sub(cookies, start, i - 1)
      elseif i == size then
        name = sub(cookies, start, i)
      end

      if name then
        name = trim(name)
        if b == SEMICOLON_BYTE or i == size then
          if name ~= "" then
            HIDE_BUFFER:put(name)
            if i ~= size then
              HIDE_BUFFER:put(";")
            end

          elseif i == size then
            break
          end

          name = nil

        else
          if name == cookie_name then
            skip = true

          elseif cookie_chunks > 1 then
            local chunk_number = tonumber(sub(name, -1), 10)
            if chunk_number and chunk_number > 1 and chunk_number <= cookie_chunks
                            and sub(name, 1, -2) == cookie_name
            then
              skip = true
            end
          end

          if not skip then
            if name ~= "" then
              HIDE_BUFFER:put(name)
            end

            if b == EQUALS_BYTE then
              HIDE_BUFFER:put("=")
            end
          end
        end

        start = i + 1
      end
    end
  end

  if #HIDE_BUFFER == 0 then
    clear_header("Cookie")
  else
    set_header("Cookie", HIDE_BUFFER:get())
  end

  return true
end


local session = {
  _VERSION = "4.0.0",
  metatable = metatable,
}


function session.init(configuration)
  if configuration then
    local ikm = configuration.ikm
    if ikm then
      DEFAULT_IKM = ikm

    else
      local secret = configuration.secret
      if secret then
        DEFAULT_IKM = assert(sha256(secret))
      end
    end

    local ikm_fallbacks = configuration.ikm_fallbacks
    if ikm_fallbacks then
      DEFAULT_IKM_FALLBACKS = ikm_fallbacks

    else
      local secret_fallbacks = configuration.secret_fallbacks
      if secret_fallbacks then
        local count = #secret_fallbacks
        if count > 0 then
          DEFAULT_IKM_FALLBACKS = table_new(count, 0)
          for i = 1, count do
            DEFAULT_IKM_FALLBACKS[i] = assert(sha256(secret_fallbacks[i]))
          end

        else
          DEFAULT_IKM_FALLBACKS = nil
        end
      end
    end

    DEFAULT_COOKIE_NAME      = configuration.cookie_name      or DEFAULT_COOKIE_NAME
    DEFAULT_COOKIE_PATH      = configuration.cookie_path      or DEFAULT_COOKIE_PATH
    DEFAULT_COOKIE_DOMAIN    = configuration.cookie_domain    or DEFAULT_COOKIE_DOMAIN
    DEFAULT_COOKIE_SAME_SITE = configuration.cookie_same_site or DEFAULT_COOKIE_SAME_SITE
    DEFAULT_COOKIE_PRIORITY  = configuration.cookie_priority  or DEFAULT_COOKIE_PRIORITY
    DEFAULT_COOKIE_PREFIX    = configuration.cookie_prefix    or DEFAULT_COOKIE_PREFIX
    DEFAULT_ABSOLUTE_TIMEOUT = configuration.absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
    DEFAULT_ROLLING_TIMEOUT  = configuration.rolling_timeout  or DEFAULT_ROLLING_TIMEOUT
    DEFAULT_IDLING_TIMEOUT   = configuration.idling_timeout   or DEFAULT_IDLING_TIMEOUT
    DEFAULT_STALE_TTL        = configuration.stale_ttl        or DEFAULT_STALE_TTL
    DEFAULT_STORAGE          = configuration.storage          or DEFAULT_STORAGE

    local cookie_http_only = configuration.cookie_http_only
    if cookie_http_only ~= nil then
      DEFAULT_COOKIE_HTTP_ONLY = cookie_http_only
    end

    local cookie_same_party = configuration.cookie_same_party
    if cookie_same_party ~= nil then
      DEFAULT_COOKIE_SAME_PARTY = cookie_same_party
    end

    local cookie_partitioned = configuration.cookie_partitioned
    if cookie_partitioned ~= nil then
      DEFAULT_COOKIE_PARTITIONED = cookie_partitioned
    end

    local cookie_secure = configuration.cookie_secure
    if cookie_secure ~= nil then
      DEFAULT_COOKIE_SECURE = cookie_secure
    end
  end

  if not DEFAULT_IKM then
    DEFAULT_IKM = assert(sha256(assert(rand_bytes(32))))
  end

  if type(DEFAULT_STORAGE) == "string" then
    DEFAULT_STORAGE = load_storage(DEFAULT_STORAGE, configuration)
  end

  return true
end


function session.new(configuration)
  local cookie_name      = configuration and configuration.cookie_name      or DEFAULT_COOKIE_NAME
  local cookie_path      = configuration and configuration.cookie_path      or DEFAULT_COOKIE_PATH
  local cookie_domain    = configuration and configuration.cookie_domain    or DEFAULT_COOKIE_DOMAIN
  local cookie_same_site = configuration and configuration.cookie_same_site or DEFAULT_COOKIE_SAME_SITE
  local cookie_priority  = configuration and configuration.cookie_priority  or DEFAULT_COOKIE_PRIORITY
  local cookie_prefix    = configuration and configuration.cookie_prefix    or DEFAULT_COOKIE_PREFIX
  local audience         = configuration and configuration.audience         or DEFAULT_AUDIENCE
  local subject          = configuration and configuration.subject          or DEFAULT_SUBJECT
  local absolute_timeout = configuration and configuration.absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
  local rolling_timeout  = configuration and configuration.rolling_timeout  or DEFAULT_ROLLING_TIMEOUT
  local idling_timeout   = configuration and configuration.idling_timeout   or DEFAULT_IDLING_TIMEOUT
  local stale_ttl        = configuration and configuration.stale_ttl        or DEFAULT_STALE_TTL
  local storage          = configuration and configuration.storage          or DEFAULT_STORAGE
  local ikm              = configuration and configuration.ikm
  local ikm_fallbacks    = configuration and configuration.ikm_fallbacks
  local options          = configuration and configuration.options

  local cookie_http_only = configuration and configuration.cookie_http_only
  if cookie_http_only == nil then
    cookie_http_only = DEFAULT_COOKIE_HTTP_ONLY
  end

  local cookie_secure = configuration and configuration.cookie_secure
  if cookie_secure == nil then
    cookie_secure = DEFAULT_COOKIE_SECURE
  end

  local cookie_same_party = configuration and configuration.cookie_same_party
  if cookie_same_party == nil then
    cookie_same_party = DEFAULT_COOKIE_SAME_PARTY
  end

  local cookie_partitioned = configuration and configuration.cookie_partitioned
  if cookie_partitioned == nil then
    cookie_partitioned = DEFAULT_COOKIE_PARTITIONED
  end

  if cookie_prefix == "__Host-" then
    cookie_name   = cookie_prefix .. cookie_name
    cookie_path   = DEFAULT_COOKIE_PATH
    cookie_domain = nil
    cookie_secure = true

  elseif cookie_prefix == "__Secure-" then
    cookie_name   = cookie_prefix .. cookie_name
    cookie_secure = true

  elseif cookie_same_site == "None" then
    cookie_secure = true
  end

  if cookie_same_party then
    assert(cookie_same_site ~= "Strict", "SameParty session cookies cannot use SameSite=Strict")
    cookie_secure = true
  end

  FLAGS_BUFFER:reset()

  if cookie_domain and cookie_domain ~= "localhost" and cookie_domain ~= "" then
    FLAGS_BUFFER:put("; Domain=", cookie_domain)
  end

  FLAGS_BUFFER:put("; Path=", cookie_path, "; SameSite=", cookie_same_site)

  if cookie_priority then
    FLAGS_BUFFER:put("; Priority=", cookie_priority)
  end

  if cookie_same_party then
    FLAGS_BUFFER:put("; SameParty")
  end

  if cookie_partitioned then
    FLAGS_BUFFER:put("; Partitioned")
  end

  if cookie_secure then
    FLAGS_BUFFER:put("; Secure")
  end

  if cookie_http_only then
    FLAGS_BUFFER:put("; HttpOnly")
  end

  local cookie_flags = FLAGS_BUFFER:get()

  if not ikm then
    local secret = configuration and configuration.secret
    if secret then
      ikm = assert(sha256(secret))

    else
      if not DEFAULT_IKM then
        DEFAULT_IKM = assert(sha256(assert(rand_bytes(32))))
      end

      ikm = DEFAULT_IKM
    end
  end

  if not ikm_fallbacks then
    local secret_fallbacks = configuration and configuration.secret_fallbacks
    if secret_fallbacks then
      local count = #secret_fallbacks
      if count > 0 then
        ikm_fallbacks = table_new(count, 0)
        for i = 1, count do
          ikm_fallbacks[i] = assert(sha256(secret_fallbacks[i]))
        end
      end

    else
      ikm_fallbacks = ikm_fallbacks or DEFAULT_IKM_FALLBACKS
    end
  end

  local opts = OPTIONS_NONE
  if options then
    local count = #options
    for i = 1, count do
      opts = bor(opts, assert(OPTIONS[options[i]]))
    end
  end

  if band(opts, OPTION_JSON) == 0 and band(opts, OPTION_STRING_BUFFER) == 0 then
    opts = bor(opts, OPTION_JSON)
  end

  if type(storage) == "string" then
    storage = load_storage(storage, configuration)

  elseif type(storage) ~= "table" then
    assert(storage == nil, "invalid session storage")
    opts = bor(opts, OPTION_STATELESS)
  end

  return setmetatable({
    absolute_timeout = absolute_timeout,
    rolling_timeout  = rolling_timeout,
    idling_timeout   = idling_timeout,
    stale_ttl        = stale_ttl,
    cookie_name      = cookie_name,
    cookie_flags     = cookie_flags,
    options          = opts,
    storage          = storage,
    ikm              = ikm,
    ikm_fallbacks    = ikm_fallbacks,
    state            = STATE_NEW,
    audience         = audience,
    meta             = DEFAULT_META,
    data             = {
      [audience]     = {
        subject      = subject,
        data         = {},
      },
    },
  }, metatable)
end


function session.open(configuration)
  local self = session.new(configuration)
  local exists, err = self:open()
  return self, err, exists
end


function session.start(configuration)
  local self, err, exists = session.open(configuration)
  if exists then
    local refreshed, err = self:refresh()
    return self, err, exists, refreshed
  end

  return self, err, exists
end


function session.destroy(configuration)
  local self, err, exists = session.open(configuration)
  if not exists then
    return nil, err, exists
  end

  local ok, err = self:destroy()
  if not ok then
    return nil, err, exists
  end

  return true, nil, exists
end


function session.logout(configuration)
  local self, err, exists = session.open(configuration)
  if not exists then
    return nil, err, exists
  end

  local ok, err = self:logout()
  if not ok then
    return nil, err, exists
  end

  return true, nil, exists
end


return session
