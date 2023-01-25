---
-- File storage utilities
--
-- @module resty.session.file.utils


local lfs = require "lfs"


local fmt = string.format
local attributes = lfs.attributes


local run_worker_thread do
  run_worker_thread = ngx.run_worker_thread
  if not run_worker_thread then
    local require = require
    run_worker_thread = function(_, module, func, ...)
      local m = require(module)
      return m[func](...)
    end
  end
end


local function get_path(storage, name, key)
  local path = storage.path
  local prefix = storage.prefix
  local suffix = storage.suffix
  if prefix and suffix then
    return fmt("%s%s_%s_%s.%s", path, prefix, name, key, suffix)
  elseif prefix then
    return fmt("%s%s_%s_%s", path, prefix, name, key)
  elseif suffix then
    return fmt("%s%s_%s.%s", path, name, key, suffix)
  else
    return fmt("%s%s_%s", path, name, key)
  end
end


local function meta_get_key(audience, subject)
  return fmt("%s:%s", audience, subject)
end


local function validate_file_attr(storage, filename)
  local path = storage.path
  local attrs, err = attributes(path .. filename)
  if err then
    return nil, err
  end

  local mode = attrs.mode
  if mode ~= "file" then
    return false
  end
  return true
end


local validate_file_name do
  local byte = string.byte
  local sub = string.sub
  local find = string.find
  local UNDERSCORE = byte("_")
  local DOT = byte(".")

  validate_file_name = function(storage, name, filename)
    if filename == "." or filename == ".." then
      return false
    end

    local plen = 0
    local prefix = storage.prefix
    if prefix then
      plen = #prefix
      if byte(filename, plen + 1) ~= UNDERSCORE then
        return false
      end
      if plen > 0 and sub(filename, 1, plen) ~= prefix then
        return false
      end
    end

    local slen = 0
    local suffix = storage.suffix
    if suffix then
      slen = #suffix
      if byte(filename, -1 - slen) ~= DOT then
        return false
      end
      if slen > 0 and sub(filename, -slen) ~= suffix then
        return false
      end
    end

    local nlen = #name
    local name_start = plen == 0 and 1 or plen + 2
    local name_end = name_start + nlen - 1
    if byte(filename, name_end + 1) ~= UNDERSCORE then
      return false
    end
    if sub(filename, name_start, name_end) ~= name then
      return false
    end

    local rest
    if slen == 0 then
      rest = sub(filename, name_end + 2)
    else
      rest = sub(filename, name_end + 2, -2 - slen)
    end
    local rlen = #rest
    if rlen < 3 then
      return false
    end

    if rlen ~= 43 then
      local colon_pos = find(rest, ":", 2, true)
      if not colon_pos or colon_pos == 43 then
        return false
      end
    end

    return true
  end
end


return {
  validate_file_name = validate_file_name,
  validate_file_attr = validate_file_attr,
  run_worker_thread = run_worker_thread,
  meta_get_key = meta_get_key,
  get_path = get_path,
}
