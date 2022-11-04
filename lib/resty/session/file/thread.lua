---
-- File storage backend worker thread module
--
-- @module resty.session.file.thread


local file_utils = require "resty.session.file.utils"
local utils = require "resty.session.utils"


local get_modification = file_utils.get_modification
local meta_get_key = file_utils.meta_get_key
local file_create = file_utils.file_create
local file_append = file_utils.file_append
local file_delete = file_utils.file_delete
local file_touch = file_utils.file_touch
local file_read = file_utils.file_read
local get_path = file_utils.get_path
local cleanup = file_utils.cleanup


local meta_get_latest = utils.meta_get_latest
local meta_get_value = utils.meta_get_value


local max = math.max


local function update_meta(path, prefix, suffix, name, meta_key, key, exp)
  local meta_value = meta_get_value(key, exp)
  if not meta_value then
    return
  end

  local file_path = get_path(path, prefix, suffix, name, meta_key)
  file_append(file_path, meta_value)
  local current_expiry = get_modification(file_path) or 0

  local new_expiry = max(current_expiry, exp)
  file_touch(file_path, new_expiry)
end


local function set(path, prefix, suffix, name, key, value, ttl,
                   current_time, old_key, stale_ttl, metadata, remember)
  local file_path = get_path(path, prefix, suffix, name, key)
  if not metadata and not old_key then
    local ok, err = file_create(file_path, value)

    if ok and current_time and ttl then
      file_touch(file_path, current_time + ttl)
    end

    cleanup(path, prefix, suffix, name, current_time)

    return ok, err
  end

  local old_ttl, old_file_path
  if old_key then
    old_file_path = get_path(path, prefix, suffix, name, old_key)
    if not remember then
      local exp = get_modification(old_file_path)
      if exp then
        old_ttl = exp - current_time
      end
    end
  end

  local ok, err = file_create(file_path, value)
  if ok and current_time and ttl then
    file_touch(file_path, current_time + ttl)
  end

  if old_file_path then
    if remember then
      file_delete(old_file_path)

    elseif not old_ttl or old_ttl > stale_ttl then
      file_touch(old_file_path, current_time + stale_ttl)
    end
  end

  if metadata then
    local audiences = metadata.audiences
    local subjects = metadata.subjects
    local count = #audiences
    for i = 1, count do
      local meta_key = meta_get_key(audiences[i], subjects[i])
      update_meta(path, prefix, suffix, name, meta_key, key, current_time + ttl)

      if old_key then
        update_meta(path, prefix, suffix, name, meta_key, old_key, 0)
      end
    end
  end

  cleanup(path, prefix, suffix, name, current_time)

  return ok, err
end


local function get(path, prefix, suffix, name, key, current_time)
  local file_path = get_path(path, prefix, suffix, name, key)

  -- TODO: do we want to check expiry here?
  -- The cookie header already has the info and has a MAC too.
  local exp = get_modification(file_path)
  if exp and exp < current_time then
    return nil, "expired"
  end

  return file_read(file_path)
end


local function delete(path, prefix, suffix, name, key, current_time, metadata)
  local file_path = get_path(path, prefix, suffix, name, key)
  file_delete(file_path)

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    local count = #audiences
    for i = 1, count do
      local meta_key = meta_get_key(audiences[i], subjects[i])
      update_meta(path, prefix, suffix, name, meta_key, key, 0)
    end
  end

  cleanup(path, prefix, suffix, name, current_time)

  return true
end


local function read_metadata(path, prefix, suffix, name, audience, subject, current_time)
  local meta_key = meta_get_key(audience, subject)
  local file_path = get_path(path, prefix, suffix, name, meta_key)
  local metadata, err = file_read(file_path)
  if not metadata then
    return nil, err
  end

  return meta_get_latest(metadata, current_time)
end


return {
  set = set,
  get = get,
  delete = delete,
  read_metadata = read_metadata,
}
