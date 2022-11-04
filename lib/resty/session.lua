local require = require


local buffer = require "string.buffer"
local bit = require "bit"


local setmetatable = setmetatable
local assert = assert
local error = error
local ceil = math.ceil
local time = ngx.time
local band = bit.band
local bor = bit.bor
local var = ngx.var
local sub = string.sub


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

-- Type (1B) || Session ID (32B) || Payload Size (4B) || Options (2B) || Creation Time (8B) || Rolling Offset (4B) || Idling Offset (2B) || Tag (16B) || Mac (6B) || Payload (*B)

local COOKIE_TYPE_SIZE = 1
local SID_SIZE = 32
local PAYLOAD_SIZE = 4
local OPTIONS_SIZE = 2
local CREATED_AT_SIZE = 8
local ROLLING_OFFSET_SIZE = 4
local IDLING_OFFSET_SIZE = 2
local TAG_SIZE = 16
local MAC_SIZE = 6
local HEADER_SIZE = COOKIE_TYPE_SIZE + SID_SIZE + PAYLOAD_SIZE + OPTIONS_SIZE + CREATED_AT_SIZE +
                    ROLLING_OFFSET_SIZE + IDLING_OFFSET_SIZE + TAG_SIZE + MAC_SIZE
local HEADER_ENCODED_SIZE = ceil(4 * HEADER_SIZE / 3) -- base64url encoded size


local COOKIE_TYPE = bpack(COOKIE_TYPE_SIZE, 1)


local COMPRESSION_THRESHOLD = 1024


local MAX_COOKIE_SIZE = 4096
local MAX_COOKIES_SIZE = 9 * MAX_COOKIE_SIZE -- 36864 bytes


local OPTIONS_NONE         = 0x0000
local OPTION_STATELESS     = 0x0001
local OPTION_JSON          = 0x0010
local OPTION_STRING_BUFFER = 0x0020
local OPTION_DEFLATE       = 0x0100


local OPTIONS = {
  json              = OPTION_JSON,
  deflate           = OPTION_DEFLATE,
  stateless         = OPTION_STATELESS,
  ["string.buffer"] = OPTION_STRING_BUFFER,
}


local DEFAULT_AUDIENCE = ""
local DEFAULT_SUBJECT  = ""


local DEFAULT_COOKIE_NAME = "session"
local DEFAULT_COOKIE_PATH = "/"
local DEFAULT_COOKIE_SAME_SITE = "Lax"
local DEFAULT_COOKIE_HTTP_ONLY = true


local DEFAULT_IDLING_TIMEOUT   = 900   -- 15 minutes
local DEFAULT_ROLLING_TIMEOUT  = 3600  -- 60 minutes
local DEFAULT_ABSOLUTE_TIMEOUT = 86400 -- 24 hours


local IKM_KEY      = {}
local AUDIENCE_KEY = {}
local DATA_KEY     = {}


local AUDIENCE_IDX = 1
local SUBJECT_IDX  = 2
local DATA_IDX     = 3


local COOKIE_WRITE_BUFFER = buffer.new(MAX_COOKIE_SIZE)
local COOKIE_FLAGS_BUFFER = buffer.new(128)
local HEADER_BUFFER       = buffer.new(HEADER_SIZE)


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


local metatable = {}


metatable.__index = metatable


function metatable.__newindex()
  error("attempt to update a read-only table", 2)
end


function metatable:set(key, value)
  self[DATA_KEY][self[AUDIENCE_KEY]][DATA_IDX][key] = value
end


function metatable:get(key)
  return self[DATA_KEY][self[AUDIENCE_KEY]][DATA_IDX][key]
end


function metatable:set_subject(subject)
  self[DATA_KEY][self[AUDIENCE_KEY]][SUBJECT_IDX] = subject
end


function metatable:get_subject()
  return self[DATA_KEY][self[AUDIENCE_KEY]][SUBJECT_IDX]
end


function metatable:set_audience(audience)
  self[DATA_KEY][self[AUDIENCE_KEY]][AUDIENCE_IDX] = audience
end


function metatable:get_audience()
  return self[DATA_KEY][self[AUDIENCE_KEY]][AUDIENCE_IDX]
end


function metatable:create()
  local options = self.options
  local stateless = band(options, OPTION_STATELESS) ~= 0
  local cookie_name = self.cookie_name
  local cookie_name_size = #cookie_name

  local data, data_size do
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
      local total_size = cookie_name_size * 9
                       + HEADER_ENCODED_SIZE
                       + data_size
                       + 17

      if total_size > MAX_COOKIES_SIZE then
        return nil, "size limit exceeded"
      end
    end
  end

  local sid, err = rand_bytes(SID_SIZE)
  if not sid then
    return nil, err
  end

  local payload_size   = bpack(PAYLOAD_SIZE, data_size)
  local options        = bpack(OPTIONS_SIZE, options)
  local created_at     = bpack(CREATED_AT_SIZE, time())
  local rolling_offset = bpack(ROLLING_OFFSET_SIZE, 0)
  local idling_offset  = bpack(IDLING_OFFSET_SIZE, 0)

  HEADER_BUFFER:reset()
  HEADER_BUFFER:put(COOKIE_TYPE, sid, payload_size, options, created_at, rolling_offset)

  local key, err, iv = derive_aes_gcm_256_key_and_iv(self[IKM_KEY], sid)
  if not key then
    return nil, err
  end

  local ciphertext, err, tag = encrypt_aes_256_gcm(key, iv, data, HEADER_BUFFER:tostring())
  if not ciphertext then
    return nil, err
  end

  HEADER_BUFFER:put(idling_offset, tag)

  local auth_key, err = derive_hmac_sha256_key(self[IKM_KEY], sid)
  if not auth_key then
    return nil, err
  end

  local mac, err = hmac_sha256(auth_key, HEADER_BUFFER:tostring())
  if not mac then
    return nil, err
  end

  local header = HEADER_BUFFER:put(sub(mac, 1, MAC_SIZE)):get()
  header, err = encode_base64url(header)
  if not header then
    return nil, err
  end

  local payload, err = encode_base64url(ciphertext)
  if not payload then
    return nil, err
  end

  -- TODO: stateless cookie splitting
  -- TODO: should just return true/false after setting the response cookie
  return COOKIE_WRITE_BUFFER:reset():put(cookie_name, "=", header, payload, self.cookie_flags):get()
end


function metatable:open(cookie)
  if not cookie then
    local cookie_name = self.cookie_name
    cookie = var["cookie_" .. cookie_name]
    if not cookie then
      return nil, "missing session cookie"
    end
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

  do
    local cookie_type = HEADER_BUFFER:get(COOKIE_TYPE_SIZE)
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
  end

  local options do
    options = HEADER_BUFFER:get(OPTIONS_SIZE)
    if #options ~= OPTIONS_SIZE then
      return nil, "invalid session options"
    end
  end

  local created_at do
    created_at = HEADER_BUFFER:get(CREATED_AT_SIZE)
    if #created_at ~= CREATED_AT_SIZE then
      return nil, "invalid session creation time"
    end
  end

  local rolling_offset do
    rolling_offset = HEADER_BUFFER:get(ROLLING_OFFSET_SIZE)
    if #rolling_offset ~= ROLLING_OFFSET_SIZE then
      return nil, "invalid session rolling offset"
    end
  end

  local idling_offset do
    idling_offset = HEADER_BUFFER:get(IDLING_OFFSET_SIZE)
    if #idling_offset ~= IDLING_OFFSET_SIZE then
      return nil, "invalid session idling offset"
    end
  end

  local tag do
    tag = HEADER_BUFFER:get(TAG_SIZE)
    if #tag ~= TAG_SIZE then
      return nil, "invalid session tag"
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

  payload_size   = bunpack(PAYLOAD_SIZE, payload_size)
  options        = bunpack(OPTIONS_SIZE, options)
  created_at     = bunpack(CREATED_AT_SIZE, created_at)
  rolling_offset = bunpack(ROLLING_OFFSET_SIZE, rolling_offset)
  idling_offset  = bunpack(IDLING_OFFSET_SIZE, idling_offset)

  local ciphertext
  if band(options, OPTION_STATELESS) then
    ciphertext = sub(cookie, -payload_size)
    if #ciphertext ~= payload_size then
      return nil, "invalid session payload"
    end

    ciphertext = decode_base64url(ciphertext)
    if not ciphertext then
      return nil, "invalid session payload"
    end

  else
    -- TODO: storage.load
    error("load data from db not implemented")
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

  local data do
    if band(options, OPTION_DEFLATE) ~= 0 then
      data = inflate(plaintext)
      if not data then
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

    local count = #data
    local current_audience = self:get_audience()
    for i = 1, count do
      if data[i][AUDIENCE_IDX] == current_audience then
        self[AUDIENCE_KEY] = i
        break
      end

      if i == count then
        -- TODO: audience validation needs to be optional
        return nil, "invalid session audience"
      end
    end
  end

  self[DATA_KEY] = data

  return true
end


local session = {
  _VERSION = "4.0.0",
}


function session.new(configuration)
  local cookie_name
  local cookie_path
  local cookie_domain
  local cookie_secure
  local cookie_prefix
  local cookie_same_site
  local cookie_http_only
  local secret
  local audience
  local absolute_timeout
  local rolling_timeout
  local idling_timeout
  local options

  if configuration then
    cookie_name      = configuration.cookie_name
    cookie_path      = configuration.cookie_path
    cookie_domain    = configuration.cookie_domain
    cookie_secure    = configuration.cookie_secure
    cookie_prefix    = configuration.cookie_prefix
    cookie_same_site = configuration.cookie_same_site
    cookie_http_only = configuration.cookie_http_only
    secret           = configuration.secret
    audience         = configuration.audience
    absolute_timeout = configuration.absolute_timeout
    rolling_timeout  = configuration.rolling_timeout
    idling_timeout   = configuration.idling_timeout
    options          = configuration.options
  end

  cookie_name      = cookie_name      or DEFAULT_COOKIE_NAME
  cookie_path      = cookie_path      or DEFAULT_COOKIE_PATH
  cookie_same_site = cookie_same_site or DEFAULT_COOKIE_SAME_SITE
  cookie_http_only = cookie_http_only or DEFAULT_COOKIE_HTTP_ONLY
  absolute_timeout = absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
  rolling_timeout  = rolling_timeout  or DEFAULT_ROLLING_TIMEOUT
  idling_timeout   = idling_timeout   or DEFAULT_IDLING_TIMEOUT
  audience         = audience         or DEFAULT_AUDIENCE

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

  COOKIE_FLAGS_BUFFER:reset()

  if cookie_domain and cookie_domain ~= "localhost" and cookie_domain ~= "" then
    COOKIE_FLAGS_BUFFER:put("; Domain=", cookie_domain)
  end

  COOKIE_FLAGS_BUFFER:put("; Path=", cookie_path, "; SameSite=", cookie_same_site)

  if cookie_secure then
    COOKIE_FLAGS_BUFFER:put("; Secure")
  end

  if cookie_http_only then
    COOKIE_FLAGS_BUFFER:put("; HttpOnly")
  end

  local cookie_flags = COOKIE_FLAGS_BUFFER:get()

  local ikm = secret
  if ikm then
    ikm = assert(sha256(ikm))
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

  -- TODO: non-stateless
  opts = bor(opts, OPTION_STATELESS)

  return setmetatable({
    absolute_timeout = absolute_timeout,
    rolling_timeout  = rolling_timeout,
    idling_timeout   = idling_timeout,
    cookie_name      = cookie_name,
    cookie_flags     = cookie_flags,
    options          = opts,
    [IKM_KEY]        = ikm,
    [AUDIENCE_KEY]   = 1,
    [DATA_KEY]       = {
      {
        [AUDIENCE_IDX] = audience,
        [SUBJECT_IDX]  = DEFAULT_SUBJECT,
        [DATA_IDX]     = {},
      },
    },
  }, metatable)
end


function session.init()
  --DEFAULT_SECRET = rand_bytes()
end


return session
