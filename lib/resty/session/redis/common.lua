---
-- Common Redis functions shared between Redis,
-- Redis Cluster and Redis Sentinel implementations.
--
-- @module resty.session.redis.cluster


local utils = require "resty.session.utils"


local meta_get_key = utils.meta_get_key
local get_name = utils.get_name
local ipairs = ipairs


local function SET(storage, red, name, key, value, ttl, current_time, old_key, stale_ttl, metadata, remember)
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
      local k = meta_get_key(storage, name, audiences[i], subjects[i])
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


local function GET(storage, red, name, key)
  return red:get(get_name(storage, name, key))
end


local function UNLINK(storage, red, name, key, current_time, metadata)
  if not metadata then
    return red:unlink(get_name(storage, name, key))
  end

  red:init_pipeline()
  red:unlink(get_name(storage, name, key))
  local audiences = metadata.audiences
  local subjects  = metadata.subjects
  local score = current_time - 1
  for i = 1, #audiences do
    local k = meta_get_key(storage, name, audiences[i], subjects[i])
    red:zremrangebyscore(k, 0, score)
    red:zrem(k, key)
  end

  return red:commit_pipeline()
end


local function READ_METADATA(storage, red, name, audience, subject, current_time)
  local sessions = {}
  local k = meta_get_key(storage, name, audience, subject)
  local res, err = red:zrange(k, current_time, "+inf", "BYSCORE", "WITHSCORES")
  if not res then
    return nil, err
  end

  for i, v in ipairs(res) do
    if i % 2 ~= 0 then
      sessions[v] = res[i + 1]
    end
  end
  return sessions
end


return {
  SET = SET,
  GET = GET,
  UNLINK = UNLINK,
  READ_METADATA = READ_METADATA,
}
