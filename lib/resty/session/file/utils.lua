---
-- File storage utilities
--
-- @module resty.session.file.utils


local lfs = require "lfs"


local attributes = lfs.attributes
local touch = lfs.touch
local dir = lfs.dir



local file_delete = os.remove
local random = math.random
local pcall = pcall
local open = io.open
local fmt = string.format
local log = ngx.log


local DEBUG = ngx.DEBUG


local CLEANUP_PROBABILITY = 0.0005 -- 1 / 2000


local run_worker_thread do
  run_worker_thread = ngx.run_worker_thread -- luacheck: ignore
  if not run_worker_thread then
    local require = require
    run_worker_thread = function(_, module, func, ...)
      local m = require(module)
      return pcall(m[func], ...)
    end
  end
end


local function file_touch(path, mtime)
  return touch(path, nil, mtime)
end


---
-- Store data in file.
--
-- @function set
-- @tparam  string   path     file path
-- @tparam  string   content  file content
-- @treturn true|nil ok
-- @treturn string   error message
local function file_create(path, content)
  local file, err = open(path, "wb")
  if not file then
    return nil, err
  end

  local ok, err = file:write(content)

  file:close()

  if not ok then
    file_delete(path)
    return nil, err
  end

  return true
end


---
-- Append data in file.
--
-- @function append
-- @tparam  string   path     file path
-- @tparam  string   data  file data
-- @treturn true|nil ok
-- @treturn string   error message
local function file_append(path, data)
  local file, err = open(path, "a")
  if not file then
    return nil, err
  end

  local ok, err = file:write(data)

  file:close()

  if not ok then
    file_delete(path)
    return nil, err
  end

  return true
end


---
-- Read data from a file.
--
-- @function get
-- @tparam  string  path file to read
-- @treturn string|nil content
-- @treturn string     error message
local function file_read(path)
  local file, err = open(path, "rb")
  if not file then
    return nil, err
  end

  local content, err = file:read("*a")

  file:close()

  if not content then
    return nil, err
  end

  return content
end


local function get_path(path, prefix, suffix, name, key)
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


local function get_modification(path)
  local attr = attributes(path)
  if not attr or attr.mode ~= "file" then
    return
  end

  return attr.modification or nil
end


local function meta_get_key(audience, subject)
  return fmt("%s:%s", audience, subject)
end


local validate_file_name do
  local byte = string.byte
  local sub = string.sub
  local find = string.find

  local UNDERSCORE = byte("_")
  local DOT = byte(".")

  validate_file_name = function(prefix, suffix, name, filename)
    if filename == "." or filename == ".." then
      return false
    end

    local plen = 0
    if prefix then
      plen = #prefix
      if byte(filename, plen + 1) ~= UNDERSCORE or
         (plen > 0 and sub(filename, 1, plen) ~= prefix) then
        return false
      end
    end

    local slen = 0
    if suffix then
      slen = #suffix

      if byte(filename, -1 - slen) ~= DOT or
         (slen > 0 and sub(filename, -slen) ~= suffix)
      then
        return false
      end
    end

    local nlen = #name
    local name_start = plen == 0 and 1 or plen + 2
    local name_end = name_start + nlen - 1

    if byte(filename, name_end + 1) ~= UNDERSCORE or
       sub(filename, name_start, name_end) ~= name
    then
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


local function cleanup(path, prefix, suffix, name, current_time)
  if random() > CLEANUP_PROBABILITY then
    return false
  end

  local deleted = 0

  log(DEBUG, "[session] expired keys cleanup initiated")

  for file in dir(path) do
    if validate_file_name(prefix, suffix, name, file) then
      local exp = get_modification(path .. file)
      if exp and exp < current_time then
        file_delete(path .. file)
        deleted = deleted + 1
      end
    end
  end

  log(DEBUG, "[session] deleted ", deleted, " files")

  return true
end


return {
  validate_file_name = validate_file_name,
  run_worker_thread = run_worker_thread,
  get_modification = get_modification,
  meta_get_key = meta_get_key,
  file_create = file_create,
  file_append = file_append,
  file_delete = file_delete,
  file_touch = file_touch,
  file_read = file_read,
  get_path = get_path,
  cleanup = cleanup,
}
