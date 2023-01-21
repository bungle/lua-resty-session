local utils = require "resty.session.utils"

local get_meta_key = utils.get_meta_key
local get_name     = utils.get_name
local time         = ngx.time

local _REDIS_COMMON = {}

function _REDIS_COMMON.SET(storage, red, name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
  if not metadata and not old_key then
    return red:set(get_name(storage, name, key), value, "EX", ttl)
  end

  local old_name
  local old_ttl
  if old_key then
    old_name = get_name(storage, name, old_key)
    if not remember then
      -- redis < 7.0
      old_ttl = red:ttl(old_name)
    end
  end

  red:init_pipeline()
  red:set(get_name(storage, name, key), value, "EX", ttl)

  -- redis < 7.0
  if old_name then
    if remember then
      red:unlink(old_name)
    elseif not old_ttl or old_ttl > stale_ttl then
      red:expire(old_name, stale_ttl)
    end
  end

  -- redis >= 7.0
  --if old_key then
  --  if remember then
  --    red:unlink(get_name(storage, name, old_key))
  --  else
  --    red:expire(get_name(storage, name, old_key), stale_ttl, "LT")
  --  end
  --end

  if metadata then
    local audiences = metadata.audiences
    local subjects  = metadata.subjects
    local score = current_time - 1
    local new_score = current_time + ttl
    for i = 1, #audiences do
      local k = get_meta_key(storage, audiences[i], subjects[i])
      red:zremrangebyscore(k, 0, score)
      red:zadd(k, new_score, key)
      if old_key then
        red:zrem(k, old_key)
      end
      red:expire(k, ttl)
    end
  end

  return red:commit_pipeline()
end

function _REDIS_COMMON.GET(storage, red, name, key)
  return red:get(get_name(storage, name, key))
end

function _REDIS_COMMON.UNLINK(storage, red, name, key, metadata)
  if not metadata then
    return red:unlink(get_name(storage, name, key))
  end

  red:init_pipeline()
  red:unlink(get_name(storage, name, key))
  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  local score = time() - 1
  for i = 1, #audiences do
    local k = get_meta_key(storage, audiences[i], subjects[i])
    red:zremrangebyscore(k, 0, score)
    red:zrem(k, key)
  end
  return red:commit_pipeline()
end

function _REDIS_COMMON.READ_METADATA(storage, red, audience, subject)
  local sessions = {}
  local k = get_meta_key(storage, audience, subject)
  local res = red:zrangebyscore(k, ngx.time(), "+inf")
  if not res then
    return nil
  end
  for _, v in ipairs(res) do
    sessions[v] = -1 -- fetch the score if needed
  end

  return sessions
end

return _REDIS_COMMON
