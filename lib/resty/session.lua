---
-- Session library.
--
-- Session library provides HTTP session management capabilities for OpenResty based
-- applications, libraries and proxies.
--
-- @module resty.session


local require = require


local table_new = require "table.new"
local buffer = require "string.buffer"
local nkeys = require "table.nkeys"
local isempty = require "table.isempty"
local utils = require "resty.session.utils"


local setmetatable = setmetatable
local clear_header = ngx.req.clear_header
local set_header = ngx.req.set_header
local http_time = ngx.http_time
local tonumber = tonumber
local assert = assert
local header = ngx.header
local error = error
local time = ngx.time
local byte = string.byte
local type = type
local sub = string.sub
local fmt = string.format
local var = ngx.var
local log = ngx.log
local max = math.max
local min = math.min


local derive_aes_gcm_256_key_and_iv = utils.derive_aes_gcm_256_key_and_iv
local derive_hmac_sha256_key = utils.derive_hmac_sha256_key
local encrypt_aes_256_gcm = utils.encrypt_aes_256_gcm
local decrypt_aes_256_gcm = utils.decrypt_aes_256_gcm
local encode_base64url = utils.encode_base64url
local decode_base64url = utils.decode_base64url
local load_storage = utils.load_storage
local encode_json = utils.encode_json
local decode_json = utils.decode_json
local base64_size = utils.base64_size
local hmac_sha256 = utils.hmac_sha256
local rand_bytes = utils.rand_bytes
local unset_flag = utils.unset_flag
local set_flag = utils.set_flag
local has_flag = utils.has_flag
local inflate = utils.inflate
local deflate = utils.deflate
local bunpack = utils.bunpack
local errmsg = utils.errmsg
local sha256 = utils.sha256
local bpack = utils.bpack
local trim = utils.trim


local NOTICE = ngx.NOTICE
local WARN   = ngx.WARN


-- Type (1B) || Options (2B) || Session ID (32B) || Creation Time (8B) || Rolling Offset (4B) || Data Size (4B) || Tag (16B) || Idling Offset (2B) || Mac (8B) || [ Data (*B) ]


local COOKIE_TYPE_SIZE    = 1
local OPTIONS_SIZE        = 2
local SID_SIZE            = 32
local CREATED_AT_SIZE     = 8
local ROLLING_OFFSET_SIZE = 4
local DATA_SIZE           = 4
local TAG_SIZE            = 16
local IDLING_OFFSET_SIZE  = 2
local MAC_SIZE            = 16


local HEADER_SIZE = COOKIE_TYPE_SIZE + OPTIONS_SIZE + SID_SIZE + CREATED_AT_SIZE + ROLLING_OFFSET_SIZE +
                    DATA_SIZE + TAG_SIZE + IDLING_OFFSET_SIZE + MAC_SIZE
local HEADER_ENCODED_SIZE = base64_size(HEADER_SIZE)


local COOKIE_TYPE = bpack(COOKIE_TYPE_SIZE, 1)


local MAX_COOKIE_SIZE    = 4096
local MAX_COOKIES        = 9
local MAX_COOKIES_SIZE   = MAX_COOKIES * MAX_COOKIE_SIZE -- 36864 bytes
local MAX_IDLING_TIMEOUT = 65535


local OPTIONS_NONE       = 0x0000
local OPTION_STATELESS   = 0x0001
local OPTION_NO_REMEMBER = 0x0002
local OPTION_DEFLATE     = 0x0010


local DEFAULT_AUDIENCE = "default"
local DEFAULT_META = {}
local DEFAULT_IKM
local DEFAULT_IKM_FALLBACKS
local DEFAULT_HASH_STORAGE_KEY = true
local DEFAULT_TOUCH_THRESHOLD = 60 -- 1 minute
local DEFAULT_COMPRESSION_THRESHOLD = 1024 -- 1 kB


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


local DEFAULT_REMEMBER_COOKIE_NAME = "remember"
local DEFAULT_REMEMBER_SAFETY = "Medium"
local DEFAULT_REMEMBER_META = false
local DEFAULT_REMEMBER = false


local DEFAULT_STALE_TTL        = 10     -- 10 seconds
local DEFAULT_IDLING_TIMEOUT   = 900    -- 15 minutes
local DEFAULT_ROLLING_TIMEOUT  = 3600   --  1 hour
local DEFAULT_ABSOLUTE_TIMEOUT = 86400  --  1 day
local DEFAULT_REMEMBER_TIMEOUT = 604800 --  1 week


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


local DATA = table_new(2, 0)


local function storage_key(sid)
  return sid
end


local function sha256_storage_key(sid)
  local key, err = sha256(sid)
  if not key then
    return nil, errmsg(err, "unable to sha256 hash session id")
  end

  key, err = encode_base64url(key)
  if not key then
    return nil, errmsg(err, "unable to base64url encode session id")
  end

  return key
end


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


local function open(self, remember, meta_only)
  local current_time = time()
  local cookie_name
  if remember then
    cookie_name = self.remember_cookie_name
  else
    cookie_name = self.cookie_name
  end

  local cookie = var["cookie_" .. cookie_name]
  if not cookie then
    return nil, "missing session cookie"
  end

  local header_decoded do
    header_decoded = sub(cookie, 1, HEADER_ENCODED_SIZE)
    if #header_decoded ~= HEADER_ENCODED_SIZE then
      return nil, "invalid session header"
    end
    local err
    header_decoded, err = decode_base64url(header_decoded)
    if not header_decoded then
      return nil, errmsg(err, "unable to base64url decode session header")
    end
  end

  HEADER_BUFFER:set(header_decoded)

  local cookie_type do
    cookie_type = HEADER_BUFFER:get(COOKIE_TYPE_SIZE)
    if #cookie_type ~= COOKIE_TYPE_SIZE then
      return nil, "invalid session cookie type"
    end
    if cookie_type ~= COOKIE_TYPE then
      return nil, "invalid session cookie type"
    end
  end

  local options do
    options = HEADER_BUFFER:get(OPTIONS_SIZE)
    if #options ~= OPTIONS_SIZE then
      return nil, "invalid session options"
    end

    options = bunpack(OPTIONS_SIZE, options)
    if has_flag(self.options, OPTION_STATELESS) ~=
            has_flag(options, OPTION_STATELESS)
    then
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

    local period = current_time - created_at
    if remember then
      local remember_timeout = self.remember_timeout
      if remember_timeout ~= 0 then
        if period > remember_timeout then
          return nil, "session remember timeout exceeded"
        end
      end

    else
      local absolute_timeout = self.absolute_timeout
      if absolute_timeout ~= 0 then
        if period > absolute_timeout then
          return nil, "session absolute timeout exceeded"
        end
      end
    end
  end

  local rolling_offset do
    rolling_offset = HEADER_BUFFER:get(ROLLING_OFFSET_SIZE)
    if #rolling_offset ~= ROLLING_OFFSET_SIZE then
      return nil, "invalid session rolling offset"
    end

    rolling_offset = bunpack(ROLLING_OFFSET_SIZE, rolling_offset)

    if not remember then
      local rolling_timeout = self.rolling_timeout
      if rolling_timeout ~= 0 then
        local rolling_period = current_time - created_at - rolling_offset
        if rolling_period > rolling_timeout then
          return nil, "session rolling timeout exceeded"
        end
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

    if remember then
      if idling_offset ~= 0 then
        return nil, "invalid session idling offset"
      end

    else
      local idling_timeout = self.idling_timeout
      if idling_timeout ~= 0 then
        local idling_period = current_time - created_at - rolling_offset - idling_offset
        if idling_period > idling_timeout then
          return nil, "session idling timeout exceeded"
        end
      end
    end
  end

  local mac, ikm do
    ikm = self.ikm
    mac = HEADER_BUFFER:get(MAC_SIZE)
    if #mac ~= MAC_SIZE then
      return nil, "invalid session message authentication code"
    end

    local msg = sub(header_decoded, 1, HEADER_SIZE - MAC_SIZE)
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

  local storage = self.storage
  local audience = self.audience
  local initial_chunk, ciphertext, ciphertext_encoded, info_data do
    if storage then
      local key, err = self.storage_key(sid)
      if not key then
        return nil, err
      end

      local data, err = storage:get(cookie_name, key, current_time)
      if not data then
        return nil, errmsg(err, "unable to load session")
      end

      data, err = decode_json(data)
      if not data then
        return nil, errmsg(err, "unable to json decode session")
      end

      ciphertext = data[1]
      ciphertext_encoded = ciphertext
      info_data = data[2]
      if info_data then
        info_data, err = decode_base64url(info_data)
        if not info_data then
          return nil, errmsg(err, "unable to base64url decode session info")
        end

        info_data, err = decode_json(info_data)
        if not info_data then
          return nil, errmsg(err, "unable to json decode session info")
        end

        if not info_data[audience] then
          info_data[audience] = self.info.data and self.info.data[audience] or nil
        end
      end

    else
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

  if remember then
    self.remember_meta = {
      options        = options,
      sid            = sid,
      created_at     = created_at,
      rolling_offset = rolling_offset,
      data_size      = data_size,
      tag            = tag,
      idling_offset  = idling_offset,
      mac            = mac,
      ikm            = ikm,
      header         = header_decoded,
      initial_chunk  = initial_chunk,
      ciphertext     = ciphertext_encoded,
    }

  else
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
      header         = header_decoded,
      initial_chunk  = initial_chunk,
      ciphertext     = ciphertext_encoded,
    }
  end

  if meta_only then
    return true
  end

  local key, err, iv
  if remember then
    key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid, self.remember_safety)
  else
    key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid)
  end

  if not key then
    return nil, errmsg(err, "unable to derive session decryption key")
  end

  local aad = sub(header_decoded, 1, HEADER_SIZE - MAC_SIZE - TAG_SIZE - IDLING_OFFSET_SIZE)
  local plaintext, err = decrypt_aes_256_gcm(key, iv, ciphertext, aad, tag)
  if not plaintext then
    return nil, errmsg(err, "unable to decrypt session data")
  end

  local data do
    if has_flag(options, OPTION_DEFLATE) then
      plaintext, err = inflate(plaintext)
      if not plaintext then
        return nil, errmsg(err, "unable to inflate session data")
      end
    end

    data, err = decode_json(plaintext)
    if not data then
      return nil, errmsg(err, "unable to json decode session data")
    end
  end

  if storage then
    self.info.data = info_data
  end

  if data[audience] == nil then
    data[audience] = self.data[audience]
    self.state = STATE_NEW
    self.data = data
    return nil, "missing session audience"
  end

  self.state = STATE_OPEN
  self.data = data

  return true
end


local function save(self, state, remember)
  local cookie_name
  local meta
  if remember then
    cookie_name = self.remember_cookie_name
    meta = self.remember_meta or {}
  else
    cookie_name = self.cookie_name
    meta = self.meta
  end

  local cookie_name_size = #cookie_name
  local options = self.options
  local storage = self.storage

  local sid, err = rand_bytes(SID_SIZE)
  if not sid then
    return nil, errmsg(err, "unable to generate session id")
  end

  local current_time = time()
  local rolling_offset

  local created_at = meta.created_at
  if created_at then
    rolling_offset = current_time - created_at

  else
    created_at = current_time
    rolling_offset = 0
  end

  do
    local meta_options = meta.options
    if meta_options and has_flag(meta_options, OPTION_NO_REMEMBER) then
      options = set_flag(options, OPTION_NO_REMEMBER)
    end
  end

  local data, data_size, cookie_chunks do
    data, err = encode_json(self.data)
    if not data then
      return nil, errmsg(err, "unable to json encode session data")
    end

    data_size = #data

    if data_size > self.compression_threshold then
      local deflated_data, err = deflate(data)
      if not deflated_data then
        log(NOTICE, "[session] unable to deflate session data (", err , ")")

      else
        if deflated_data then
          local deflated_size = #deflated_data
          if deflated_size < data_size then
            options = set_flag(options, OPTION_DEFLATE)
            data = deflated_data
            data_size = deflated_size
          end
        end
      end
    end

    data_size = base64_size(data_size)

    if storage then
      cookie_chunks = 1
    else
      cookie_chunks, err = calculate_cookie_chunks(cookie_name_size, data_size)
      if not cookie_chunks then
        return nil, err
      end
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
  local key, iv
  if remember then
    key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid, self.remember_safety)
  else
    key, err, iv = derive_aes_gcm_256_key_and_iv(ikm, sid)
  end

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

  local header_decoded = HEADER_BUFFER:put(sub(mac, 1, MAC_SIZE)):get()
  local header_encoded, err = encode_base64url(header_decoded)
  if not header_encoded then
    return nil, errmsg(err, "unable to base64url encode session header")
  end

  local payload, err = encode_base64url(ciphertext)
  if not payload then
    return nil, errmsg(err, "unable to base64url encode session data")
  end

  local cookies = header["Set-Cookie"]
  local cookie_flags = self.cookie_flags

  local initial_chunk
  local ciphertext_encoded

  local remember_flags
  if remember then
    local max_age = self.remember_timeout
    local expires = http_time(created_at + max_age)
    remember_flags = fmt("; Expires=%s; Max-Age=%d", expires, max_age)
  end

  if cookie_chunks == 1 then
    local cookie_data
    if storage then
      ciphertext_encoded = payload
      if remember then
        cookie_data = fmt("%s=%s%s%s", cookie_name, header_encoded, cookie_flags, remember_flags)
      else
        cookie_data = fmt("%s=%s%s", cookie_name, header_encoded, cookie_flags)
      end

    else
      initial_chunk = payload
      if remember then
        cookie_data = fmt("%s=%s%s%s%s", cookie_name, header_encoded, payload, cookie_flags, remember_flags)
      else
        cookie_data = fmt("%s=%s%s%s", cookie_name, header_encoded, payload, cookie_flags)
      end
    end

    cookies, err = merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
    if not cookies then
      return nil, err
    end

  else
    DATA_BUFFER:set(payload)

    initial_chunk = DATA_BUFFER:get(MAX_COOKIE_SIZE - HEADER_ENCODED_SIZE - cookie_name_size - 1)

    local cookie_data
    if remember then
      cookie_data = fmt("%s=%s%s%s%s", cookie_name, header_encoded, initial_chunk, cookie_flags, remember_flags)
    else
      cookie_data = fmt("%s=%s%s%s", cookie_name, header_encoded, initial_chunk, cookie_flags)
    end

    cookies, err = merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
    if not cookies then
      return nil, err
    end

    for i = 2, cookie_chunks do
      local name = fmt("%s%d", cookie_name, i)
      cookie_data = DATA_BUFFER:get(MAX_COOKIE_SIZE - cookie_name_size - 2)
      if remember then
        cookie_data = fmt("%s=%s%s%s", name, cookie_data, cookie_flags, remember_flags)
      else
        cookie_data = fmt("%s=%s%s", name, cookie_data, cookie_flags)
      end
      cookies, err = merge_cookies(cookies, cookie_name_size + 1, name, cookie_data)
      if not cookies then
        return nil, err
      end
    end
  end

  if storage then
    local key, err = self.storage_key(sid)
    if not key then
      return nil, err
    end

    DATA[1] = payload

    local info_data = self.info.data
    if info_data then
      info_data, err = encode_json(info_data)
      if not info_data then
        return nil, errmsg(err, "unable to json encode session info")
      end

      info_data, err = encode_base64url(info_data)
      if not info_data then
        return nil, errmsg(err, "unable to base64url encode session info")
      end

      DATA[2] = info_data

    else
      DATA[2] = nil
    end

    data, err = encode_json(DATA)
    if not data then
      return nil, errmsg(err, "unable to json encode session data")
    end

    local ok
    if remember then
      ok, err = storage:set(cookie_name, key, data, self.remember_timeout, current_time)
    else
      ok, err = storage:set(cookie_name, key, data, self.rolling_timeout, current_time)
    end
    if not ok then
      return nil, errmsg(err, "unable to store session data")
    end

    local old_sid = meta.sid
    if old_sid then
      if remember then
        key, err = self.storage_key(old_sid)
        if key then
          local ok, err = storage:delete(cookie_name, key)
          if not ok then
            log(WARN, "[session] unable to delete session (", err , ")")
          end

        else
          log(WARN, "[session] ", err)
        end

      elseif storage.expire then
        key, err = self.storage_key(old_sid)
        if key then
          local stale_ttl = self.stale_ttl
          if storage.ttl then
            local ttl = storage:ttl(cookie_name, key)
            if ttl and ttl > stale_ttl then
              local ok, err = storage:expire(cookie_name, key, stale_ttl, current_time)
              if not ok then
                log(WARN, "[session] unable to expire session (", err , ")")
              end
            end

          else
            ok, err = storage:expire(cookie_name, key, stale_ttl, current_time)
            if not ok then
              log(WARN, "[session] unable to expire session (", err , ")")
            end
          end

        else
          log(WARN, "[session] ", err)
        end
      end
    end

  else
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
  end

  header["Set-Cookie"] = cookies

  if remember then
    self.remember_meta = {
      options        = options,
      sid            = sid,
      created_at     = created_at,
      rolling_offset = rolling_offset,
      data_size      = data_size,
      tag            = tag,
      idling_offset  = idling_offset,
      mac            = mac,
      ikm            = ikm,
      header         = header_decoded,
      initial_chunk  = initial_chunk,
      ciphertext     = ciphertext_encoded,
    }

  else
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
      header         = header_decoded,
      initial_chunk  = initial_chunk,
      ciphertext     = ciphertext_encoded,
    }
  end

  return true
end


local function save_info(self, data, remember)
  local cookie_name
  local meta
  if remember then
    cookie_name = self.remember_cookie_name
    meta = self.remember_meta or {}
  else
    cookie_name = self.cookie_name
    meta = self.meta
  end

  local key, err = self.storage_key(meta.sid)
  if not key then
    return nil, err
  end

  DATA[1] = meta.ciphertext
  DATA[2] = data

  data, err = encode_json(DATA)
  if not data then
    return nil, errmsg(err, "unable to json encode session data")
  end

  local current_time = time()

  local ttl = max(self.rolling_timeout - (current_time - meta.created_at -  meta.rolling_offset), 1)
  local ok, err = self.storage:set(cookie_name, key, data, ttl, current_time)
  if not ok then
    return nil, errmsg(err, "unable to store session info")
  end
end


local function destroy(self, remember)
  local cookie_name
  local meta
  if remember then
    cookie_name = self.remember_cookie_name
    meta = self.remember_meta or {}
  else
    cookie_name = self.cookie_name
    meta = self.meta
  end

  local cookie_name_size = #cookie_name
  local storage = self.storage

  local cookie_chunks = 1
  local data_size = meta.data_size
  if not storage and data_size then
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

  if storage then
    local sid = meta.sid
    if sid then
      local key, err = self.storage_key(sid)
      if not key then
        return nil, err
      end

      local ok, err = storage:delete(cookie_name, key)
      if not ok then
        return nil, errmsg(err, "unable to destroy session")
      end
    end
  end

  header["Set-Cookie"] = cookies

  self.state = STATE_CLOSED

  return true
end


local function hide(remember)
  assert(self.state == STATE_OPEN, "unable to hide nonexistent session")

  local cookies = var.http_cookie
  if not cookies or cookies == "" then
    return
  end

  local cookie_name
  if remember then
    cookie_name = self.remember_cookie_name
  else
    cookie_name = self.cookie_name
  end

  local cookie_name_size = #cookie_name

  local cookie_chunks
  if self.storage then
    cookie_chunks = 1
  else
    local data_size = remember and self.remember_meta.data_size or self.meta.data_size
    cookie_chunks = calculate_cookie_chunks(cookie_name_size, data_size) or 1
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



local function get_remember(self)
  local options = self.meta.options
  if options and has_flag(options, OPTION_NO_REMEMBER) then
    return false
  end

  if has_flag(self.options, OPTION_NO_REMEMBER) then
    return false
  end

  return self.remember
end


--- Session
-- @section instance


local info_mt = {}


info_mt.__index = info_mt


---
-- Set a value in session information store.
--
-- @function instance.info:set
-- @tparam string key   key
-- @tparam string value value
function info_mt:set(key, value)
  local session = self.session

  assert(session.state ~= STATE_CLOSED, "unable to set session info on closed session")

  local audience = session.audience
  local data = self.data
  if data then
    if data[audience] then
      data[audience][key] = value

    else
      data[audience] = {
        [key] = value,
      }
    end

  else
    self.data = {
      [audience] = {
        [key] = value,
      },
    }
  end
end


---
-- Get a value from session information store.
--
-- @function instance.info:get
-- @tparam string key key
-- @return value
function info_mt:get(key)
  local session = self.session

  assert(session.state ~= STATE_CLOSED, "unable to get session info on closed session")

  local data = self.data
  if not data then
    return
  end

  data = self.data[session.audience]
  if not data then
    return
  end

  return data[key]
end


---
-- Save information.
--
-- Only updates backend storage. Does not send a new cookie.
--
-- @function instance.info:save
-- @treturn true|nil ok
-- @treturn string   error message
function info_mt:save()
  local session = self.session
  assert(session.state == STATE_OPEN, "unable to save session info on nonexistent or closed session")

  local data = self.data
  if not data then
    return true
  end

  local err
  data, err = encode_json(data)
  if not data then
    return nil, errmsg(err, "unable to json encode session info")
  end

  data, err = encode_base64url(data)
  if not data then
    return nil, errmsg(err, "unable to base64url encode session info")
  end

  local ok, err = save_info(session, data)
  if not ok then
    return nil, err
  end

  if session.remember then
    if not session.remember_meta then
      local remembered = open(self, true, true)
      if not remembered then
        return save(session, nil, true)
      end
    end

    return save_info(session, data, true)
  end

  return true
end


local info = {}


function info.new(session)
  return setmetatable({
    session = session,
    data = false,
  }, info_mt)
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


---
-- Set a value in session.
--
-- @function instance:set
-- @tparam string key   key
-- @tparam string value value
function metatable:set(key, value)
  assert(self.state ~= STATE_CLOSED, "unable to set session data on closed session")
  self.data[self.audience].data[key] = value
end


---
-- Get a value from session.
--
-- @function instance:get
-- @tparam string key key
-- @return value
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


function metatable:set_remember(value)
  assert(self.state ~= STATE_CLOSED, "unable to set remember on closed session")
  assert(type(value) == "boolean", "invalid remember value")
  if value == false then
    set_flag(self.options, OPTION_NO_REMEMBER)
  else
    unset_flag(self.options, OPTION_NO_REMEMBER)
  end

  self.remember = value
end


function metatable:get_remember()
  assert(self.state ~= STATE_CLOSED, "unable to get remember on closed session")
  return get_remember(self)
end


---
-- Open a session.
--
-- This can be used to open a session. It will either return an existing
-- session or a new session.
--
-- @function instance:open
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:open()
  local exists, err = open(self)
  if exists then
    return true
  end

  if not self.remember then
    return nil, err
  end

  local remembered, err2 = open(self, true)
  if not remembered then
    return nil, errmsg(err2, err)
  end

  local ok, err = save(self, nil, true)
  if not ok then
    return nil, err
  end

  self.state = STATE_NEW
  self.meta = DEFAULT_META

  local ok, err = save(self, STATE_OPEN)
  if not ok then
    return nil, err
  end

  return true
end


---
-- Save the session.
--
-- Saves the session data and issues a new session cookie with a new session id.
-- When `remember`  is enabled, it will also issue a new persistent cookie and
-- possibly save the data in backend store.
--
-- @function instance:save
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:save()
  assert(self.state ~= STATE_CLOSED, "unable to save closed session")

  local ok, err = save(self)
  if not ok then
    return nil, err
  end

  if get_remember(self) then
    if not self.remember_meta then
      open(self, true, true)
    end

    local ok, err = save(self, nil, true)
    if not ok then
      log(WARN, "[session] ", err)
    end
  end

  return true
end


---
-- Touch the session.
--
-- Updates idling offset of the session by sending an updated session cookie.
-- It only sends the client cookie and never calls any backend session store
-- APIs. Normally the `session:refresh` is used to call this indirectly.
--
-- @function instance:touch
-- @treturn true|nil ok
-- @treturn string   error message
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
  if has_flag(meta.options, OPTION_STATELESS) then
    cookie_data = fmt("%s=%s%s%s", cookie_name, payload_header, meta.initial_chunk, cookie_flags)
  else
    cookie_data = fmt("%s=%s%s", cookie_name, payload_header, cookie_flags)
  end

  header["Set-Cookie"] = merge_cookies(header["Set-Cookie"], #cookie_name, cookie_name, cookie_data)

  return true
end


---
-- Refresh the session.
--
-- Either saves the session (creating a new session id) or touches the session
-- depending on whether the rolling timeout is getting closer. The touch has
-- a threshold, by default one minute, so it may be skipped in some cases.
--
-- @function instance:refresh
-- @treturn true|nil ok
-- @treturn string   error message
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

  local time_passed_after_previous_save = time() - created_at - rolling_offset
  local time_to_rolling_expiry = rolling_timeout - time_passed_after_previous_save
  if time_to_rolling_expiry > idling_timeout then
    local idling_offset = meta.idling_offset
    if idling_offset then
      local time_passed_after_previous_touch = time_passed_after_previous_save - idling_offset
      if time_passed_after_previous_touch > self.touch_threshold then
        return self:touch()

      else
        return false
      end

    else
      return self:touch()
    end
  end

  return save(self)
end


---
-- Logout the session.
--
-- Logout either destroys the session or just clears the data for the current audience,
-- and saves it (logging out from the current audience).
--
-- @function instance:logout
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:logout()
  assert(self.state == STATE_OPEN, "unable to logout nonexistent or closed session")

  local data = self.data
  if nkeys(data) == 1 then
    return self:destroy()
  end

  local audience = self.audience
  data[audience] = nil
  local info = self.info
  if info and info.data then
    info.data[audience] = nil
    if isempty(info.data) then
      info.data = nil
    end
  end

  local ok, err = save(self, STATE_CLOSED)
  if not ok then
    return nil, err
  end

  if get_remember(self) then
    if not self.remember_meta then
      open(self, true, true)
    end
    local ok, err = save(self, nil, true)
    if not ok then
      log(WARN, "[session] ", err)
    end
  end

  return true
end


---
-- Destroy the session.
--
-- Destroy the session and clear the cookies.
--
-- @function instance:destroy
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:destroy()
  assert(self.state == STATE_OPEN, "unable to destroy nonexistent or closed session")

  local ok, err = destroy(self)
  if not ok then
    return nil, err
  end

  if get_remember(self) then
    if not self.remember_meta then
      local remembered = open(self, true, true)
      if not remembered then
        return true
      end
    end

    ok, err = destroy(self, true)
    if not ok then
      return nil, err
    end
  end

  return true
end


---
-- Close the session.
--
-- Just closes the session instance so that it cannot be used anymore.
--
-- @function instance:close
-- @treturn true|nil ok
-- @treturn string   error message
function metatable:close()
  self.state = STATE_CLOSED
  return true
end


---
-- Hide the session.
--
-- Modifies the request headers by removing the session related
-- cookies. This is useful when you use the session library on
-- a proxy server and don't want the session cookies to be forwarded
-- to the upstream service.
--
-- @function instance:hide
-- @treturn true|nil ok
function metatable:hide()
  local ok = hide(self)
  if not ok then
    log(NOTICE, "[session] unable to hide session")
  end

  if get_remember(self) then
    local ok2 = hide(self, true)
    if not ok2 then
      log(NOTICE, "[session] unable to hide persistent session")
      return false
    end
  end

  return ok
end



local session = {
  _VERSION = "4.0.0",
  metatable = metatable,
}


--- Configuration
-- @section configuration


---
-- Session configuration.
-- @field secret Secret used for the key derivation. The secret is hashed with SHA-256 before using it. E.g. `"RaJKp8UQW1"`.
-- @field secret_fallbacks Array of secrets that can be used as alternative secrets (when doing key rotation), E.g. `{ "6RfrAYYzYq", "MkbTkkyF9C" }`.
-- @field ikm Initial key material (or ikm) can be specified directly (without using a secret) with exactly 32 bytes of data, e.g. `"5ixIW4QVMk0dPtoIhn41Eh1I9enP2060"`
-- @field ikm_fallbacks Array of initial key materials that can be used as alternative keys (when doing key rotation), E.g. `{ "QvPtlPKxOKdP5MCu1oI3lOEXIVuDckp7" }`.
-- @field cookie_prefix Cookie prefix, use `nil`, `"__Host-"` or `"__Secure-"` (defaults to `nil`)
-- @field cookie_name Session cookie name, e.g. `"session"` (defaults to `"session"`)
-- @field cookie_path Cookie path, e.g. `"/"` (defaults to `"/"`)
-- @field cookie_domain Cookie domain, e.g. `"example.com"` (defaults to `nil`)
-- @field cookie_http_only Mark cookie HTTP only, use `true` or `false` (defaults to `true`)
-- @field cookie_secure Mark cookie secure, use `nil`, `true` or `false` (defaults to `nil`)
-- @field cookie_priority Cookie priority, use `nil`, `"Low"`, `"Medium"`, or `"High"` (defaults to `nil`)
-- @field cookie_same_site Cookie same-site policy, use `nil`, `"Lax"`, `"Strict"`, or `"None"` (defaults to `"Lax"`)
-- @field cookie_same_party Mark cookie with same party flag, use `nil`, `true`, or `false` (default: `nil`)
-- @field cookie_partitioned Mark cookie with partitioned flag, use `nil`, `true`, or `false` (default: `nil`)
-- @field remember Enable or disable persistent sessions, use `nil`, `true`, or `false` (defaults to `false`)
-- @field remember_safety Remember cookie key derivation complexity, use `nil`, `"Low"` (fast), `"Medium"`, or `"High"` (slow) (defaults to `"Medium"`)
-- @field remember_cookie_name Persistent session cookie name, e.g. `"remember"` (defaults to `"remember"`)
-- @field audience Session audience, e.g. `"my-application"` (defaults to `"default"`)
-- @field subject Session subject, e.g. `"john.doe@example.com"` (defaults to `nil`)
-- @field stale_ttl When session is saved a new session is created, stale ttl specifies how long the old one can still be used, e.g. `10` (defaults to `10`) (in seconds)
-- @field idling_timeout Idling timeout specifies how long the session can be inactive until it is considered invalid, e.g. `900` (defaults to `900`, or 15 minutes) (in seconds)
-- @field rolling_timeout Rolling timeout specifies how long the session can be used until it needs to be renewed, e.g. `3600` (defaults to `3600`, or an hour) (in seconds)
-- @field absolute_timeout Absolute timeout limits how long the session can be renewed, until re-authentication is required, e.g. `86400` (defaults to `86400`, or a day) (in seconds)
-- @field remember_timeout Remember timeout specifies how long the persistent session is considered valid, e.g. `604800` (defaults to `604800`, or a week) (in seconds)
-- @field hash_storage_key Whether to hash or not the storage key. With storage key hashed it is impossible to decrypt data on server side without having a cookie too (defaults to `true`).
-- @field touch_threshold Touch threshold controls how frequently or infrequently the `session:refresh` touches the cookie, e.g. `60` (defaults to `60`, or a minute) (in seconds)
-- @field compression_threshold Compression threshold controls when the data is deflated, e.g. `1024` (defaults to `1024`, or a kilobyte) (in bytes)
-- @field storage Storage is responsible of storing session data, use `nil` (data is stored in cookie), `dshm`, `file`, `memcached`, `mysql`, `postgres`, `redis`, `redis-cluster`, `redis-sentinel`, or `shm`, or give a name of custom module (`"custom.session.storage"`), or a `table` that implements session storage interface (defaults to `nil`)
-- @field dshm Configuration for dshm storage, e.g. `{ prefix = "sessions" }`
-- @field file Configuration for file storage, e.g. `{ path = "/tmp", suffix = "session" }`
-- @field memcached Configuration for memcached storage, e.g. `{ prefix = "sessions" }`
-- @field mysql Configuration for MySQL / MariaDB storage, e.g. `{ database = "sessions" }`
-- @field postgres Configuration for Postgres storage, e.g. `{ database = "sessions" }`
-- @field redis Configuration for Redis / Redis Sentinel / Redis Cluster storages, e.g. `{ prefix = "sessions" }`
-- @field shm Configuration for shared memory storage, e.g. `{ zone = "sessions" }`
-- @field ["resty.session.custom-storage"] sssadws
-- @table configuration


--- Initialization
-- @section initialization


---
-- Initialize the session library.
--
-- This function can be called on `init` or `init_worker` phases on OpenResty
-- to set global default configuration to all session instances created by this
-- library.
--
-- @function module.init
-- @tparam[opt] table configuration  session @{configuration} overrides
--
-- @usage
-- require "resty.session".init({
--   audience = "my-application",
-- })
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

    DEFAULT_COOKIE_NAME           = configuration.cookie_name           or DEFAULT_COOKIE_NAME
    DEFAULT_COOKIE_PATH           = configuration.cookie_path           or DEFAULT_COOKIE_PATH
    DEFAULT_COOKIE_DOMAIN         = configuration.cookie_domain         or DEFAULT_COOKIE_DOMAIN
    DEFAULT_COOKIE_SAME_SITE      = configuration.cookie_same_site      or DEFAULT_COOKIE_SAME_SITE
    DEFAULT_COOKIE_PRIORITY       = configuration.cookie_priority       or DEFAULT_COOKIE_PRIORITY
    DEFAULT_COOKIE_PREFIX         = configuration.cookie_prefix         or DEFAULT_COOKIE_PREFIX
    DEFAULT_REMEMBER_SAFETY       = configuration.remember_safety       or DEFAULT_REMEMBER_SAFETY
    DEFAULT_REMEMBER_COOKIE_NAME  = configuration.remember_cookie_name  or DEFAULT_REMEMBER_COOKIE_NAME
    DEFAULT_AUDIENCE              = configuration.audience              or DEFAULT_AUDIENCE
    DEFAULT_STALE_TTL             = configuration.stale_ttl             or DEFAULT_STALE_TTL
    DEFAULT_IDLING_TIMEOUT        = configuration.idling_timeout        or DEFAULT_IDLING_TIMEOUT
    DEFAULT_ROLLING_TIMEOUT       = configuration.rolling_timeout       or DEFAULT_ROLLING_TIMEOUT
    DEFAULT_ABSOLUTE_TIMEOUT      = configuration.absolute_timeout      or DEFAULT_ABSOLUTE_TIMEOUT
    DEFAULT_REMEMBER_TIMEOUT      = configuration.remember_timeout      or DEFAULT_REMEMBER_TIMEOUT
    DEFAULT_TOUCH_THRESHOLD       = configuration.touch_threshold       or DEFAULT_TOUCH_THRESHOLD
    DEFAULT_COMPRESSION_THRESHOLD = configuration.compression_threshold or DEFAULT_COMPRESSION_THRESHOLD
    DEFAULT_STORAGE               = configuration.storage               or DEFAULT_STORAGE

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

    local remember = configuration.remember
    if remember ~= nil then
      DEFAULT_REMEMBER = remember
    end

    local hash_storage_key = configuration.hash_storage_key
    if hash_storage_key ~= nil then
      DEFAULT_HASH_STORAGE_KEY = hash_storage_key
    end
  end

  if not DEFAULT_IKM then
    DEFAULT_IKM = assert(sha256(assert(rand_bytes(32))))
  end

  if type(DEFAULT_STORAGE) == "string" then
    DEFAULT_STORAGE = load_storage(DEFAULT_STORAGE, configuration)
  end
end


--- Constructors
-- @section constructors

---
-- Create a new session.
--
-- This creates a new session instance.
--
-- @function module.new
-- @tparam[opt]  table   configuration  session @{configuration} overrides
-- @treturn      table                  session instance
--
-- @usage
-- local session = require "resty.session".new()
-- -- OR
-- local session = require "resty.session".new({
--   audience = "my-application",
-- })
function session.new(configuration)
  local cookie_name           = configuration and configuration.cookie_name           or DEFAULT_COOKIE_NAME
  local cookie_path           = configuration and configuration.cookie_path           or DEFAULT_COOKIE_PATH
  local cookie_domain         = configuration and configuration.cookie_domain         or DEFAULT_COOKIE_DOMAIN
  local cookie_same_site      = configuration and configuration.cookie_same_site      or DEFAULT_COOKIE_SAME_SITE
  local cookie_priority       = configuration and configuration.cookie_priority       or DEFAULT_COOKIE_PRIORITY
  local cookie_prefix         = configuration and configuration.cookie_prefix         or DEFAULT_COOKIE_PREFIX
  local remember_safety       = configuration and configuration.remember_safety       or DEFAULT_REMEMBER_SAFETY
  local remember_cookie_name  = configuration and configuration.remember_cookie_name  or DEFAULT_REMEMBER_COOKIE_NAME
  local audience              = configuration and configuration.audience              or DEFAULT_AUDIENCE
  local subject               = configuration and configuration.subject
  local stale_ttl             = configuration and configuration.stale_ttl             or DEFAULT_STALE_TTL
  local idling_timeout        = configuration and configuration.idling_timeout        or DEFAULT_IDLING_TIMEOUT
  local rolling_timeout       = configuration and configuration.rolling_timeout       or DEFAULT_ROLLING_TIMEOUT
  local absolute_timeout      = configuration and configuration.absolute_timeout      or DEFAULT_ABSOLUTE_TIMEOUT
  local remember_timeout      = configuration and configuration.remember_timeout      or DEFAULT_REMEMBER_TIMEOUT
  local touch_threshold       = configuration and configuration.touch_threshold       or DEFAULT_TOUCH_THRESHOLD
  local compression_threshold = configuration and configuration.compression_threshold or DEFAULT_COMPRESSION_THRESHOLD
  local storage               = configuration and configuration.storage               or DEFAULT_STORAGE
  local ikm                   = configuration and configuration.ikm
  local ikm_fallbacks         = configuration and configuration.ikm_fallbacks

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

  local remember = configuration and configuration.remember
  if remember == nil then
    remember = DEFAULT_REMEMBER
  end

  local hash_storage_key = configuration and configuration.hash_storage_key
  if hash_storage_key == nil then
    hash_storage_key = DEFAULT_HASH_STORAGE_KEY
  end

  if cookie_prefix == "__Host-" then
    cookie_name          = cookie_prefix .. cookie_name
    remember_cookie_name = cookie_prefix .. remember_cookie_name
    cookie_path          = DEFAULT_COOKIE_PATH
    cookie_domain        = nil
    cookie_secure        = true

  elseif cookie_prefix == "__Secure-" then
    cookie_name          = cookie_prefix .. cookie_name
    remember_cookie_name = cookie_prefix .. remember_cookie_name
    cookie_secure        = true

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

  local options = OPTIONS_NONE
  local t = type(storage)
  if t == "string" then
    storage = load_storage(storage, configuration)

  elseif t ~= "table" then
    assert(storage == nil, "invalid session storage")
    options = set_flag(options, OPTION_STATELESS)
  end

  local self = setmetatable({
    stale_ttl             = stale_ttl,
    idling_timeout        = idling_timeout,
    rolling_timeout       = rolling_timeout,
    absolute_timeout      = absolute_timeout,
    remember_timeout      = remember_timeout,
    touch_threshold       = touch_threshold,
    compression_threshold = compression_threshold,
    storage_key           = hash_storage_key and sha256_storage_key or storage_key,
    cookie_name           = cookie_name,
    cookie_flags          = cookie_flags,
    remember_cookie_name  = remember_cookie_name,
    remember_safety       = remember_safety,
    remember              = remember,
    options               = options,
    storage               = storage,
    ikm                   = ikm,
    ikm_fallbacks         = ikm_fallbacks,
    state                 = STATE_NEW,
    audience              = audience,
    meta                  = DEFAULT_META,
    remember_meta         = DEFAULT_REMEMBER_META,
    info                  = storage and info or nil,
    data                  = {
      [audience]          = {
        subject           = subject,
        data              = {},
      },
    },
  }, metatable)

  if storage then
    self.info = info.new(self)
  end

  return self
end


--- Helpers
-- @section helpers


---
-- Open a session.
--
-- This can be used to open a session, and it will either return an existing
-- session or a new session.
--
-- @function module.open
-- @tparam[opt]  table   configuration  session @{configuration} overrides
-- @treturn      table                  session instance
-- @treturn      string                 error message
-- @treturn      boolean                `true`, if session existed, otherwise `false`
--
-- @usage
-- local session = require "resty.session".open()
-- -- OR
-- local session, err, exists = require "resty.session".open({
--   audience = "my-application",
-- })
function session.open(configuration)
  local self = session.new(configuration)
  local exists, err = self:open()
  if not exists then
    return self, err, false
  end

  return self, err, true
end


---
-- Start a session and refresh it as needed.
--
-- This can be used to start a session, and it will either return an existing
-- session or a new session. In case there is an existing session, the
-- session will be refreshed as well (as needed).
--
-- @function module.start
-- @tparam[opt]  table   configuration  session @{configuration} overrides
-- @treturn      table                  session instance
-- @treturn      string                 error message
-- @treturn      boolean                `true`, if session existed, otherwise `false`
-- @treturn      boolean                `true`, if session was refreshed, otherwise `false`
--
-- @usage
-- local session = require "resty.session".start()
-- -- OR
-- local session, err, exists, refreshed = require "resty.session".start()
--   audience = "my-application",
-- })
function session.start(configuration)
  local self, err, exists = session.open(configuration)
  if not exists then
    return self, err, false, false
  end

  local refreshed, err = self:refresh()
  if not refreshed then
    return self, err, true, false
  end

  return self, nil, true, true
end


---
-- Logout a session.
--
-- It logouts from a specific audience.
--
-- A single session cookie may be shared between multiple audiences
-- (or applications), thus there is a need to be able to logout from
-- just a single audience while keeping the session for the other
-- audiences.
--
-- When there is only a single audience, then this can be considered
-- equal to `session.destroy`.
--
-- When the last audience is logged out, the cookie will be destroyed
-- as well and invalidated on a client.
--
-- @function module.logout
-- @tparam[opt]  table    configuration  session @{configuration} overrides
-- @treturn      boolean                 `true` session exists for an audience and was logged out successfully, otherwise `false`
-- @treturn      string                  error message
-- @treturn      boolean                 `true` if session existed, otherwise `false`
-- @treturn      boolean                 `true` if session was logged out, otherwise `false`
--
-- @usage
-- require "resty.session".logout()
-- -- OR
-- local ok, err, exists, logged_out = require "resty.session".logout({
--   audience = "my-application",
-- })
function session.logout(configuration)
  local self, err, exists = session.open(configuration)
  if not exists then
    return nil, err, false, false
  end

  local ok, err = self:logout()
  if not ok then
    return nil, err, true, false
  end

  return true, nil, true, true
end

---
-- Destroy a session.
--
-- It destroys the whole session and clears the cookies.
--
-- @function module.destroy
-- @tparam[opt]  table    configuration  session @{configuration} overrides
-- @treturn      boolean                 `true` session exists and was destroyed successfully, otherwise `nil`
-- @treturn      string                  error message
-- @treturn      boolean                 `true` if session existed, otherwise `false`
-- @treturn      boolean                 `true` if session was destroyed, otherwise `false`
--
-- @usage
-- require "resty.session".destroy()
-- -- OR
-- local ok, err, exists = require "resty.session".destroy({
--   cookie_name = "auth",
-- })
function session.destroy(configuration)
  local self, err, exists = session.open(configuration)
  if not exists then
    return nil, err, false, false
  end

  local ok, err = self:destroy()
  if not ok then
    return nil, err, true, false
  end

  return true, nil, true, true
end


function session.__set_ngx_log(ngx_log)
  log = ngx_log
end


function session.__set_ngx_var(ngx_var)
  var = ngx_var
end


function session.__set_ngx_header(ngx_header)
  header = ngx_header
end


function session.__set_ngx_req_clear_header(ngx_clear_header)
  clear_header = ngx_clear_header
end


function session.__set_ngx_req_set_header(ngx_set_header)
  set_header = ngx_set_header
end


return session
