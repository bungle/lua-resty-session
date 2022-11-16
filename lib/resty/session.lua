local require = require


local buffer = require "string.buffer"
local bit = require "bit"


local setmetatable = setmetatable
local clear_header = ngx.req.clear_header
local set_header = ngx.req.set_header
local tonumber = tonumber
local assert = assert
local remove = table.remove
local header = ngx.header
local error = error
local ceil = math.ceil
local time = ngx.time
local band = bit.band
local byte = string.byte
local type = type
local sub = string.sub
local fmt = string.format
local bor = bit.bor
local var = ngx.var
local min = math.min


local EQUALS_BYTE = byte("=")
local SEMICOLON_BYTE = byte(";")


local bpack, bunpack do
  local binpack
  local binunpack

  local SIZE_TO_FORMAT = {
    [1] = "<C",
    [2] = "<S",
    [4] = "<I",
    [8] = "<L",
  }

  local function bpack_real(size, value)
    return binpack(SIZE_TO_FORMAT[size], value)
  end

  local function bunpack_real(size, value)
    local _, value = binunpack(value, SIZE_TO_FORMAT[size])
    return value
  end

  bpack = function(size, value)
    if not binpack then
       binpack = require "lua_pack".pack
    end
    bpack = bpack_real
    return bpack(size, value)
  end

  bunpack = function(size, value)
    if not binunpack then
      binunpack = require "lua_pack".unpack
    end
    bunpack = bunpack_real
    return bunpack(size, value)
  end
end

-- Type (1B) || Session ID (32B) || Payload Size (4B) || Options (2B) || Creation Time (8B) || Rolling Offset (4B) || Tag (16B) || Idling Offset (2B) || Mac (6B) || [ Payload (*B) ]

local COOKIE_TYPE_SIZE = 1
local SID_SIZE = 32
local PAYLOAD_SIZE = 4
local OPTIONS_SIZE = 2
local CREATED_AT_SIZE = 8
local ROLLING_OFFSET_SIZE = 4
local TAG_SIZE = 16
local IDLING_OFFSET_SIZE = 2
local MAC_SIZE = 6
local HEADER_SIZE = COOKIE_TYPE_SIZE + SID_SIZE + PAYLOAD_SIZE + OPTIONS_SIZE + CREATED_AT_SIZE +
                    ROLLING_OFFSET_SIZE + TAG_SIZE + IDLING_OFFSET_SIZE + MAC_SIZE
local HEADER_ENCODED_SIZE = ceil(4 * HEADER_SIZE / 3) -- base64url encoded size


local COOKIE_TYPE = bpack(COOKIE_TYPE_SIZE, 1)


local COMPRESSION_THRESHOLD = 1024


local MAX_COOKIE_SIZE = 4096
local MAX_COOKIES = 9
local MAX_STATELESS_SIZE = MAX_COOKIES * MAX_COOKIE_SIZE -- 36864 bytes


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
local DEFAULT_SUBJECT  = ""
local DEFAULT_META     = {}
local DEFAULT_IKM


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


local MAX_IDLING_TIMEOUT = 65535


local IKM_KEY      = {}
local STATE_KEY    = {}
local AUDIENCE_KEY = {}
local META_KEY     = {}
local DATA_KEY     = {}


local AUDIENCE_IDX = 1
local SUBJECT_IDX  = 2
local DATA_IDX     = 3


local STATE_NEW    = 0
local STATE_OPEN   = 1
local STATE_CLOSED = 2


local HEADER_BUFFER  = buffer.new(HEADER_SIZE)
local PAYLOAD_BUFFER = buffer.new(MAX_STATELESS_SIZE)
local FLAGS_BUFFER   = buffer.new(128)
local HIDE_BUFFER    = buffer.new(256)


local COOKIE_EXPIRE_FLAGS = "; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0"


local trim do
  local SPACE_BYTE = byte(" ")
  local TAB_BYTE = byte("\t")
  local CR_BYTE = byte("\r")
  local LF_BYTE = byte("\n")
  local VTAB_BYTE = byte("\v")
  local FF_BYTE = byte("\f")

  trim = function(value)
    if value == nil or value == "" then
      return ""
    end

    local len = #value

    local s = 1
    for i = 1, len do
      local b = byte(value, i)
      if b == SPACE_BYTE
      or b == TAB_BYTE
      or b == CR_BYTE
      or b == LF_BYTE
      or b == VTAB_BYTE
      or b == FF_BYTE
      then
        s = s + 1
      else
        break
      end
    end

    local e = len
    for i = len, 1, -1 do
      local b = byte(value, i)
      if b == SPACE_BYTE
      or b == TAB_BYTE
      or b == CR_BYTE
      or b == LF_BYTE
      or b == VTAB_BYTE
      or b == FF_BYTE
      then
        e = e - 1
      else
        break
      end
    end

    if s ~= 1 or e ~= len then
      return sub(value, s, e)
    end

    return value
  end
end


local encode_buffer, decode_buffer do
  local buf_enc = buffer.new(192)
  local buf_dec = buffer.new(192)
  encode_buffer = function(value)
    -- TODO: do we need to pcall?
    return buf_enc:reset():encode(value):get()
  end
  decode_buffer = function(value)
    -- TODO: do we need to pcall?
    return buf_dec:set(value):decode()
  end
end


local encode_json, decode_json do
  local cjson
  encode_json = function(value)
    if not cjson then
      cjson = require "cjson.safe".new()
    end
    encode_json = cjson.encode
    return encode_json(value)
  end
  decode_json = function(value)
    if not cjson then
      cjson = require "cjson.safe".new()
    end
    decode_json = cjson.decode
    return decode_json(value)
  end
end


local encode_base64url, decode_base64url do
  local base64
  encode_base64url = function(value)
    if not base64 then
      base64 = require "ngx.base64"
    end
    encode_base64url = base64.encode_base64url
    return encode_base64url(value)
  end
  decode_base64url = function(value)
    if not base64 then
      base64 = require "ngx.base64"
    end
    decode_base64url = base64.decode_base64url
    return decode_base64url(value)
  end
end


local deflate, inflate do
  local DEFLATE_WINDOW_BITS = -15
  local DEFLATE_CHUNK_SIZE = 8192
  local DEFLATE_OPTIONS = {
    windowBits = DEFLATE_WINDOW_BITS,
  }

  local zlib
  local input_buffer = buffer.new()
  local output_buffer = buffer.new()

  local function prepare_buffers(input)
    input_buffer:set(input)
    output_buffer:reset()
  end

  local function read_input_buffer(size)
    local data = input_buffer:get(size)
    return data ~= "" and data or nil
  end

  local function write_output_buffer(data)
    return output_buffer:put(data)
  end

  local function gzip(inflate_or_deflate, input, chunk_size, window_bits_or_options)
    prepare_buffers(input)
    local ok, err = inflate_or_deflate(read_input_buffer, write_output_buffer,
                                       chunk_size, window_bits_or_options)
    if not ok then
      return nil, err
    end

    return output_buffer:tostring()
  end

  local function deflate_real(data)
    return gzip(zlib.deflateGzip, data, DEFLATE_CHUNK_SIZE, DEFLATE_OPTIONS)
  end

  local function inflate_real(data)
    return gzip(zlib.inflateGzip, data, DEFLATE_CHUNK_SIZE, DEFLATE_WINDOW_BITS)
  end

  deflate = function(data)
    if not zlib then
      zlib = require "ffi-zlib"
    end
    deflate = deflate_real
    return deflate(data)
  end

  inflate = function(data)
    if not zlib then
      zlib = require "ffi-zlib"
    end
    inflate = inflate_real
    return inflate(data)
  end
end


local rand_bytes do
  local rand
  rand_bytes = function(length)
    if not rand then
      rand = require "resty.openssl.rand"
    end
    rand_bytes = rand.bytes
    return rand_bytes(length)
  end
end


local sha256 do
  local digest
  local sha256_digest

  local function sha256_real(value)
    local _, err, output
    if not sha256_digest then
      sha256_digest, err = digest.new("sha256")
      if err then
        return nil, err
      end
    end

    output, err = sha256_digest:final(value)
    if err then
      sha256_digest = nil
      return nil, err
    end

    _, err = sha256_digest:reset()
    if err then
      sha256_digest = nil
    end

    return output
  end

  sha256 = function(value)
    if not digest then
      digest = require "resty.openssl.digest"
    end
    sha256 = sha256_real
    return sha256(value)
  end
end


local derive_hkdf_sha256 do
  local kdf_derive

  local EXTRACTED_KEYS = {}

  local HKDF_SHA256_EXTRACT_OPTS
  local HKDF_SHA256_EXPAND_OPTS

  local function derive_hkdf_sha256_real(ikm, nonce, usage, size)
    local err
    local key = EXTRACTED_KEYS[ikm]
    if not key then
      HKDF_SHA256_EXTRACT_OPTS.hkdf_key = ikm
      key, err = kdf_derive(HKDF_SHA256_EXTRACT_OPTS)
      HKDF_SHA256_EXTRACT_OPTS.hkdf_key = ""
      if not key then
        return nil, err
      end
      EXTRACTED_KEYS[ikm] = key
    end

    HKDF_SHA256_EXPAND_OPTS.hkdf_key = key
    HKDF_SHA256_EXPAND_OPTS.hkdf_info = usage .. ":" .. nonce
    HKDF_SHA256_EXPAND_OPTS.outlen = size
    key, err = kdf_derive(HKDF_SHA256_EXPAND_OPTS)
    if not key then
      return nil, err
    end

    return key
  end

  derive_hkdf_sha256 = function(ikm, nonce, usage, size)
    if not kdf_derive then
      local kdf = require "resty.openssl.kdf"
      HKDF_SHA256_EXTRACT_OPTS = {
        type = kdf.HKDF,
        outlen = 32,
        md = "sha256",
        salt = "",
        hkdf_key = "",
        hkdf_mode = kdf.HKDEF_MODE_EXTRACT_ONLY,
        hkdf_info = "",
      }
      HKDF_SHA256_EXPAND_OPTS = {
        type = kdf.HKDF,
        outlen = 0,
        md = "sha256",
        salt = "",
        hkdf_key = "",
        hkdf_mode = kdf.HKDEF_MODE_EXPAND_ONLY,
        hkdf_info = "",
      }
      kdf_derive = kdf.derive
    end
    derive_hkdf_sha256 = derive_hkdf_sha256_real
    return derive_hkdf_sha256(ikm, nonce, usage, size)
  end
end


local function derive_aes_gcm_256_key_and_iv(ikm, nonce)
  local bytes, err = derive_hkdf_sha256(ikm, nonce, "encryption", 44)
  if not bytes then
    return nil, err
  end

  local key = sub(bytes, 1, 32)  -- 32 bytes
  local iv  = sub(bytes, 33, 44) -- 12 bytes

  return key, nil, iv
end


local function derive_hmac_sha256_key(ikm, nonce)
  return derive_hkdf_sha256(ikm, nonce, "authentication", 32)
end


local encrypt_aes_256_gcm, decrypt_aes_256_gcm do
  local AES_256_GCP_CIPHER = "aes-256-gcm"
  local AES_256_GCM_TAG_SIZE = 16

  local cipher_aes_256_gcm
  local function encrypt_aes_256_gcm_real(key, iv, plaintext, aad)
    local ciphertext, err = cipher_aes_256_gcm:encrypt(key, iv, plaintext, false, aad)
    if not ciphertext then
      return nil, err
    end

    local tag, err = cipher_aes_256_gcm:get_aead_tag(AES_256_GCM_TAG_SIZE)
    if not tag then
      return nil, err
    end

    return ciphertext, nil, tag
  end

  local function decrypt_aes_256_gcm_real(key, iv, ciphertext, aad, tag)
    return cipher_aes_256_gcm:decrypt(key, iv, ciphertext, false, aad, tag)
  end

  encrypt_aes_256_gcm = function(key, iv, plaintext, aad)
    if not cipher_aes_256_gcm then
      cipher_aes_256_gcm = require("resty.openssl.cipher").new(AES_256_GCP_CIPHER)
    end
    encrypt_aes_256_gcm = encrypt_aes_256_gcm_real
    return encrypt_aes_256_gcm(key, iv, plaintext, aad)
  end

  decrypt_aes_256_gcm = function(key, iv, ciphertext, aad, tag)
    if not cipher_aes_256_gcm then
      cipher_aes_256_gcm = require("resty.openssl.cipher").new(AES_256_GCP_CIPHER)
    end
    decrypt_aes_256_gcm = decrypt_aes_256_gcm_real
    return decrypt_aes_256_gcm(key, iv, ciphertext, aad, tag)
  end
end


local hmac_sha256 do
  local hmac
  local HMAC_SHA256_DIGEST = "sha256"

  local function hmac_sha256_real(key, value)
    local mac, err = hmac.new(key, HMAC_SHA256_DIGEST)
    if not mac then
      return nil, err
    end

    local digest, err = mac:final(value)
    if not digest then
      return nil, err
    end

    return digest
  end

  hmac_sha256 = function(key, value)
    if not hmac then
      hmac = require "resty.openssl.hmac"
    end
    hmac_sha256 = hmac_sha256_real
    return hmac_sha256(key, value)
  end
end


local function load_storage(storage, configuration)
  if storage == "file" then
    return require("resty.session.file").new(configuration and configuration.file)

  elseif storage == "memcached" then
    return require("resty.session.memcached").new(configuration and configuration.memcached)

  elseif storage == "redis" then
    local cfg = configuration and configuration.redis
    if cfg then
      if cfg.nodes then
        return require("resty.session.redis-cluster").new(cfg)
      elseif cfg.sentinels then
        return require("resty.session.redis-sentinel").new(cfg)
      end
    end

    return require("resty.session.redis").new(cfg)

  elseif storage == "shm" then
    return require("resty.session.shm").new(configuration and configuration.shm)

  else
    return require(storage).new(configuration and configuration[storage])
  end
end


local function calculate_cookie_chunks(cookie_name_size, data_size)
  local space_needed = cookie_name_size + 1 + HEADER_ENCODED_SIZE + data_size
  if space_needed > MAX_STATELESS_SIZE then
    return nil, "size limit exceeded"
  end

  if space_needed <= MAX_COOKIE_SIZE then
    return 1
  end

  for i = 2, MAX_COOKIES do
    space_needed = space_needed + cookie_name_size + 2
    if space_needed > MAX_STATELESS_SIZE then
      return nil, "size limit exceeded"
    elseif space_needed <= (MAX_COOKIE_SIZE * i) then
      return i
    end
  end

  return nil, "size limit exceeded"
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
    return nil, "invalid cookies"
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


local function get_meta(self, name)
  if self[STATE_KEY] ~= STATE_OPEN then
    return
  end

  return self[META_KEY][name]
end


local function save(self, state)
  local options = self.options
  local stateless = band(options, OPTION_STATELESS) ~= 0
  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local data, data_size, cookie_chunks do
    local err
    if band(options, OPTION_STRING_BUFFER) ~= 0 then
      data, err = encode_buffer(self[DATA_KEY])
      if not data then
        return nil, err
      end

    else
      data, err = encode_json(self[DATA_KEY])
      if not data then
        return nil, err
      end

      options = bor(options, OPTION_JSON)
    end

    data_size = #data

    if data_size > COMPRESSION_THRESHOLD then
      local deflated_data = deflate(data)
      if deflated_data then
        local deflated_size = #deflated_data
        if deflated_size < data_size then
          options = bor(options, OPTION_DEFLATE)
          data = deflated_data
          data_size = deflated_size
        end
      end
    end

    data_size = ceil(4 * data_size / 3) -- base64url encoded size

    if stateless then
      cookie_chunks, err = calculate_cookie_chunks(cookie_name_size, data_size)
      if not cookie_chunks then
        return nil, err
      end

    else
      cookie_chunks = 1
    end
  end

  local sid, err = rand_bytes(SID_SIZE)
  if not sid then
    return nil, err
  end

  local meta = self[META_KEY]

  local current_time = time()
  local created_at = meta.created_at
  local rolling_offset
  if created_at then
    rolling_offset = current_time - created_at
  else
    created_at = current_time
    rolling_offset = 0
  end

  local idling_offset = 0

  local packed_data_size      = bpack(PAYLOAD_SIZE, data_size)
  local packed_options        = bpack(OPTIONS_SIZE, options)
  local packed_created_at     = bpack(CREATED_AT_SIZE, created_at)
  local packed_rolling_offset = bpack(ROLLING_OFFSET_SIZE, rolling_offset)
  local packed_idling_offset  = bpack(IDLING_OFFSET_SIZE, idling_offset)

  HEADER_BUFFER:reset()
  HEADER_BUFFER:put(COOKIE_TYPE, sid, packed_data_size, packed_options, packed_created_at, packed_rolling_offset)

  local key, err, iv = derive_aes_gcm_256_key_and_iv(self[IKM_KEY], sid)
  if not key then
    return nil, err
  end

  local ciphertext, err, tag = encrypt_aes_256_gcm(key, iv, data, HEADER_BUFFER:tostring())
  if not ciphertext then
    return nil, err
  end

  HEADER_BUFFER:put(tag, packed_idling_offset)

  local auth_key, err = derive_hmac_sha256_key(self[IKM_KEY], sid)
  if not auth_key then
    return nil, err
  end

  local mac, err = hmac_sha256(auth_key, HEADER_BUFFER:tostring())
  if not mac then
    return nil, err
  end

  local payload_header = HEADER_BUFFER:put(sub(mac, 1, MAC_SIZE)):get()
  payload_header, err = encode_base64url(payload_header)
  if not payload_header then
    return nil, err
  end

  local payload, err = encode_base64url(ciphertext)
  if not payload then
    return nil, err
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
    PAYLOAD_BUFFER:set(payload)

    initial_chunk = PAYLOAD_BUFFER:get(MAX_COOKIE_SIZE - HEADER_ENCODED_SIZE - cookie_name_size - 1)

    local cookie_data = fmt("%s=%s%s%s", cookie_name, payload_header, initial_chunk, cookie_flags)
    cookies, err = merge_cookies(cookies, cookie_name_size, cookie_name, cookie_data)
    if not cookies then
      return nil, err
    end

    for i = 2, cookie_chunks do
      local name = fmt("%s%d", cookie_name, i)
      cookie_data = PAYLOAD_BUFFER:get(MAX_COOKIE_SIZE - cookie_name_size - 2)
      cookie_data = fmt("%s=%s%s", name, cookie_data, cookie_flags)
      cookies, err = merge_cookies(cookies, cookie_name_size + 1, name, cookie_data)
      if not cookies then
        return nil, err
      end
    end
  end

  if stateless then
    local old_data_size = meta.size
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
      return nil, err
    end

    local storage = self.storage
    local ok, err = storage:set(key, payload, self.rolling_timeout)
    if not ok then
      return nil, err
    end

    if storage.expire then
      local old_sid = meta.id
      if old_sid then
        key, err = encode_base64url(old_sid)
        if not key then
          return nil, err
        end

        local stale_ttl = self.stale_ttl
        if storage.ttl then
          local ttl = storage:ttl(key)
          if ttl and ttl > stale_ttl then
            local ok, err = storage:expire(key, stale_ttl)
            if not ok then
              -- TODO: log or ignore?
            end
          end

        else
          local ok, err = storage:expire(key, stale_ttl)
          if not ok then
            -- TODO: log or ignore?
          end
        end
      end
    end
  end

  header["Set-Cookie"] = cookies

  self[STATE_KEY] = state or STATE_OPEN
  self[META_KEY] = {
    id = sid,
    size = data_size,
    options = options,
    created_at = created_at,
    rolling_offset = rolling_offset,
    tag = tag,
    idling_offset = idling_offset,
    mac = mac,
    header = header,
    initial_chunk = initial_chunk,
  }

  return true
end


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value)
  if self[STATE_KEY] ~= STATE_CLOSED then
    self[DATA_KEY][self[AUDIENCE_KEY]][DATA_IDX][key] = value
  end
end


function metatable:get(key)
  if self[STATE_KEY] ~= STATE_CLOSED then
    return self[DATA_KEY][self[AUDIENCE_KEY]][DATA_IDX][key]
  end
end


function metatable:set_subject(subject)
  if self[STATE_KEY] ~= STATE_CLOSED then
    self[DATA_KEY][self[AUDIENCE_KEY]][SUBJECT_IDX] = subject
  end
end


function metatable:get_subject()
  if self[STATE_KEY] ~= STATE_CLOSED then
    return self[DATA_KEY][self[AUDIENCE_KEY]][SUBJECT_IDX]
  end
end


function metatable:set_audience(audience)
  if self[STATE_KEY] ~= STATE_CLOSED then
    self[DATA_KEY][self[AUDIENCE_KEY]][AUDIENCE_IDX] = audience
  end
end


function metatable:get_audience()
  if self[STATE_KEY] ~= STATE_CLOSED then
    return self[DATA_KEY][self[AUDIENCE_KEY]][AUDIENCE_IDX]
  end
end


function metatable:get_id()
  return get_meta(self, "id")
end


function metatable:get_size()
  return get_meta(self, "size")
end


function metatable:get_created_at()
  return get_meta(self, "created_at")
end


function metatable:get_rolling_offset()
  return get_meta(self, "rolling_offset")
end


function metatable:get_tag()
  return get_meta(self, "tag")
end


function metatable:get_idling_offset()
  return get_meta(self, "idling_offset")
end


function metatable:get_mac()
  return get_meta(self, "mac")
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
    header = decode_base64url(header)
    if not header then
      return nil, "invalid session header"
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

  local sid do
    sid = HEADER_BUFFER:get(SID_SIZE)
    if #sid ~= SID_SIZE then
      return nil, "invalid session id"
    end
  end

  local payload_size do
    payload_size = HEADER_BUFFER:get(PAYLOAD_SIZE)
    if #payload_size ~= PAYLOAD_SIZE then
      return nil, "invalid session payload size"
    end

    payload_size = bunpack(PAYLOAD_SIZE, payload_size)
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

  local mac do
    mac = HEADER_BUFFER:get(MAC_SIZE)
    if #mac ~= MAC_SIZE then
      return nil, "invalid session mac"
    end

    local key, err = derive_hmac_sha256_key(self[IKM_KEY], sid)
    if not key then
      return nil, err
    end

    local expected_mac, err = hmac_sha256(key, sub(header, 1, HEADER_SIZE - MAC_SIZE))
    if not expected_mac then
      return nil, err
    end

    expected_mac = sub(expected_mac, 1, MAC_SIZE)
    if mac ~= expected_mac then
      return nil, "invalid session mac"
    end
  end

  local initial_chunk, ciphertext do
    if stateless then
      local cookie_chunks, err = calculate_cookie_chunks(#cookie_name, payload_size)
      if not cookie_chunks then
        return nil, err
      end

      if cookie_chunks == 1 then
        initial_chunk = sub(cookie, -payload_size)
        ciphertext = initial_chunk

      else
        initial_chunk = sub(cookie, HEADER_ENCODED_SIZE + 1)
        PAYLOAD_BUFFER:reset():put(initial_chunk)
        for i = 2, cookie_chunks do
          local chunk = var["cookie_" .. cookie_name .. i]
          if not chunk then
            return nil, "missing session cookie chunk"
          end

          PAYLOAD_BUFFER:put(chunk)
        end

        ciphertext = PAYLOAD_BUFFER:get()
      end

      if #ciphertext ~= payload_size then
        return nil, "invalid session payload"
      end

      ciphertext = decode_base64url(ciphertext)
      if not ciphertext then
        return nil, "invalid session payload"
      end

    else
      local key, err = encode_base64url(sid)
      if not key then
        return nil, err
      end

      ciphertext = self.storage:get(key)
      if not ciphertext then
        return nil, "invalid session payload"
      end

      if #ciphertext ~= payload_size then
        return nil, "invalid session payload"
      end

      ciphertext = decode_base64url(ciphertext)
      if not ciphertext then
        return nil, "invalid session payload"
      end
    end
  end

  local key, err, iv = derive_aes_gcm_256_key_and_iv(self[IKM_KEY], sid)
  if not key then
    return nil, err
  end

  local aad = sub(header, 1, HEADER_SIZE - MAC_SIZE - TAG_SIZE - IDLING_OFFSET_SIZE)
  local plaintext = decrypt_aes_256_gcm(key, iv, ciphertext, aad, tag)
  if not plaintext then
    return nil, "invalid session payload"
  end

  local data, audience_count, audience_index do
    if band(options, OPTION_DEFLATE) ~= 0 then
      plaintext = inflate(plaintext)
      if not plaintext then
        return nil, "invalid session payload"
      end
    end

    if band(options, OPTION_JSON) ~= 0 then
      data = decode_json(plaintext)
    elseif band(options, OPTION_STRING_BUFFER) ~= 0 then
      data = decode_buffer(plaintext)
    end

    if not data then
      return nil, "invalid session payload"
    end

    audience_count = #data
    local current_audience = self:get_audience()
    for i = 1, audience_count do
      if data[i][AUDIENCE_IDX] == current_audience then
        audience_index = i
        break
      end
    end
  end

  self[META_KEY] = {
    id = sid,
    size = payload_size,
    options = options,
    created_at = created_at,
    rolling_offset = rolling_offset,
    tag = tag,
    idling_offset = idling_offset,
    mac = mac,
    header = header,
    initial_chunk = initial_chunk,
  }

  if not audience_index then
    local current_data = self[DATA_KEY][self[AUDIENCE_KEY]]
    self[STATE_KEY] = STATE_NEW
    self[AUDIENCE_KEY] = audience_count + 1
    data[self[AUDIENCE_KEY]] = current_data
    return nil, "invalid session audience"
  end

  self[STATE_KEY] = STATE_OPEN
  self[AUDIENCE_KEY] = audience_index
  self[DATA_KEY] = data

  return true
end


function metatable:save()
  return save(self)
end


function metatable:touch()
  if self[STATE_KEY] ~= STATE_OPEN then
    return nil, "unable to touch nonexistent session"
  end

  local meta = self[META_KEY]
  local idling_offset = min(time() - meta.created_at - meta.rolling_offset, MAX_IDLING_TIMEOUT)

  HEADER_BUFFER:reset():put(sub(meta.header, 1, HEADER_SIZE - IDLING_OFFSET_SIZE - MAC_SIZE),
                            bpack(IDLING_OFFSET_SIZE, idling_offset))

  -- TODO: we need to know if the session was opened with a fallback IKM
  local auth_key, err = derive_hmac_sha256_key(self[IKM_KEY], meta.id)
  if not auth_key then
    return nil, err
  end

  local mac, err = hmac_sha256(auth_key, HEADER_BUFFER:tostring())
  if not mac then
    return nil, err
  end

  mac = sub(mac, 1, MAC_SIZE)

  local payload_header = HEADER_BUFFER:put(mac):get()

  self[META_KEY].idling_offset = idling_offset
  self[META_KEY].mac = mac
  self[META_KEY].header = payload_header

  payload_header, err = encode_base64url(payload_header)
  if not payload_header then
    return nil, err
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
  if self[STATE_KEY] ~= STATE_OPEN then
    return nil, "unable to refresh nonexistent session"
  end

  local meta = self[META_KEY]
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
  if self[STATE_KEY] ~= STATE_OPEN then
    return nil, "unable to logout nonexistent session"
  end

  if #self[DATA_KEY] == 1 then
    return self:destroy()
  end

  remove(self[DATA_KEY], self[AUDIENCE_KEY])

  return save(self, STATE_CLOSED)
end


function metatable:destroy()
  if self[STATE_KEY] ~= STATE_OPEN then
    return nil, "unable to destroy nonexistent session"
  end

  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local meta = self[META_KEY]
  local stateless = band(self.options, OPTION_STATELESS) ~= 0

  local cookie_flags = self.cookie_flags

  local cookie_chunks = 1
  local data_size = meta.size
  if stateless and data_size then
    cookie_chunks = calculate_cookie_chunks(cookie_name_size, data_size)
  end

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
    local key, err = encode_base64url(meta.id)
    if not key then
      return nil, err
    end
    self.storage:delete(key)
  end

  header["Set-Cookie"] = cookies

  self[STATE_KEY] = STATE_CLOSED

  return true
end


function metatable:hide(ngx_var)
  if self[STATE_KEY] ~= STATE_OPEN then
    return nil, "unable to hide nonexistent session"
  end

  local cookies = (ngx_var or var).http_cookie
  if not cookies or cookies == "" then
    return
  end

  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local stateless = band(self.options, OPTION_STATELESS) ~= 0

  local cookie_chunks
  if stateless then
    cookie_chunks = calculate_cookie_chunks(cookie_name_size, self[META_KEY].size) or 1
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
    local secret = configuration.secret
    if secret then
      DEFAULT_IKM = assert(sha256(secret))
    end

    DEFAULT_COOKIE_NAME       = configuration.cookie_name      or DEFAULT_COOKIE_NAME
    DEFAULT_COOKIE_PATH       = configuration.cookie_path      or DEFAULT_COOKIE_PATH
    DEFAULT_COOKIE_DOMAIN     = configuration.cookie_domain    or DEFAULT_COOKIE_DOMAIN
    DEFAULT_COOKIE_SAME_SITE  = configuration.cookie_same_site or DEFAULT_COOKIE_SAME_SITE
    DEFAULT_COOKIE_PRIORITY   = configuration.cookie_priority  or DEFAULT_COOKIE_PRIORITY
    DEFAULT_COOKIE_PREFIX     = configuration.cookie_prefix    or DEFAULT_COOKIE_PREFIX
    DEFAULT_ABSOLUTE_TIMEOUT  = configuration.absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
    DEFAULT_ROLLING_TIMEOUT   = configuration.rolling_timeout  or DEFAULT_ROLLING_TIMEOUT
    DEFAULT_IDLING_TIMEOUT    = configuration.idling_timeout   or DEFAULT_IDLING_TIMEOUT
    DEFAULT_STALE_TTL         = configuration.stale_ttl        or DEFAULT_STALE_TTL
    DEFAULT_STORAGE           = configuration.storage          or DEFAULT_STORAGE

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
    local default_secret = assert(rand_bytes(32))
    DEFAULT_IKM = assert(sha256(default_secret))
  end

  if type(DEFAULT_STORAGE) == "string" then
    DEFAULT_STORAGE = load_storage(DEFAULT_STORAGE, configuration)
  end

  return true
end


function session.new(configuration)
  local cookie_name       = configuration and configuration.cookie_name      or DEFAULT_COOKIE_NAME
  local cookie_path       = configuration and configuration.cookie_path      or DEFAULT_COOKIE_PATH
  local cookie_domain     = configuration and configuration.cookie_domain    or DEFAULT_COOKIE_DOMAIN
  local cookie_same_site  = configuration and configuration.cookie_same_site or DEFAULT_COOKIE_SAME_SITE
  local cookie_priority   = configuration and configuration.cookie_priority  or DEFAULT_COOKIE_PRIORITY
  local cookie_prefix     = configuration and configuration.cookie_prefix    or DEFAULT_COOKIE_PREFIX
  local audience          = configuration and configuration.audience         or DEFAULT_AUDIENCE
  local absolute_timeout  = configuration and configuration.absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
  local rolling_timeout   = configuration and configuration.rolling_timeout  or DEFAULT_ROLLING_TIMEOUT
  local idling_timeout    = configuration and configuration.idling_timeout   or DEFAULT_IDLING_TIMEOUT
  local stale_ttl         = configuration and configuration.stale_ttl        or DEFAULT_STALE_TTL
  local storage           = configuration and configuration.storage          or DEFAULT_STORAGE
  local secret            = configuration and configuration.secret
  local options           = configuration and configuration.options

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

  local ikm
  if secret then
    ikm = assert(sha256(secret))

  else
    if not DEFAULT_IKM then
      local default_secret = assert(rand_bytes(32))
      DEFAULT_IKM = assert(sha256(default_secret))
    end

    ikm = DEFAULT_IKM
  end

  local opts = OPTIONS_NONE
  if options then
    local count = #options
    for i = 1, count do
      opts = bor(opts, assert(OPTIONS[options[i]]))
    end
  end

  if band(opts, OPTION_JSON)          == 0 and
     band(opts, OPTION_STRING_BUFFER) == 0
  then
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
    [IKM_KEY]        = ikm,
    [STATE_KEY]      = STATE_NEW,
    [AUDIENCE_KEY]   = 1,
    [META_KEY]       = DEFAULT_META,
    [DATA_KEY]       = {
      {
        [AUDIENCE_IDX] = audience,
        [SUBJECT_IDX]  = DEFAULT_SUBJECT,
        [DATA_IDX]     = {},
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
    return nil, err
  end

  local ok, err = self:destroy()
  if not ok then
    return nil, err, exists
  end

  return true, nil, exists
end


return session
