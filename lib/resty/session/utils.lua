local require = require


local buffer = require "string.buffer"


local byte = string.byte
local sub  = string.sub


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


local trim do
  local SPACE_BYTE = byte(" ")
  local TAB_BYTE   = byte("\t")
  local CR_BYTE    = byte("\r")
  local LF_BYTE    = byte("\n")
  local VTAB_BYTE  = byte("\v")
  local FF_BYTE    = byte("\f")

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
    return buf_enc:reset():encode(value):get()
  end
  decode_buffer = function(value)
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

  elseif storage == "mysql" then
    return require("resty.session.mysql").new(configuration and configuration.mysql)

  elseif storage == "postgres" then
    return require("resty.session.postgres").new(configuration and configuration.postgres)

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


return {
  bpack = bpack,
  bunpack = bunpack,
  trim = trim,
  encode_buffer = encode_buffer,
  decode_buffer = decode_buffer,
  encode_json = encode_json,
  decode_json = decode_json,
  encode_base64url = encode_base64url,
  decode_base64url = decode_base64url,
  inflate = inflate,
  deflate = deflate,
  rand_bytes = rand_bytes,
  sha256 = sha256,
  derive_hkdf_sha256 = derive_hkdf_sha256,
  derive_aes_gcm_256_key_and_iv = derive_aes_gcm_256_key_and_iv,
  derive_hmac_sha256_key = derive_hmac_sha256_key,
  encrypt_aes_256_gcm = encrypt_aes_256_gcm,
  decrypt_aes_256_gcm = decrypt_aes_256_gcm,
  hmac_sha256 = hmac_sha256,
  load_storage = load_storage,
}
