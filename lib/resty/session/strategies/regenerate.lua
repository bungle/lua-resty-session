local type   = type
local time   = ngx.time
local concat = table.concat

local regenerate = {}

-- save the session data to the underlying storage adapter.
-- @param session_obj (table) the session object to store
-- @return result from `storage.save`.
function regenerate.save(session_obj, close)
  local id, expires, storage = session_obj.id, session_obj.expires, session_obj.storage
  if storage.ttl then
    -- if there is a ttl, then we set the lifetime to the 'discard' value as a
    -- grace period
    storage:ttl(id, session_obj.cookie.discard)
  end

  -- recreate a new ID, since the old one has a temporary discard-ttl
  id = session_obj:identifier()
  session_obj.id = id

  local key = session_obj.hmac(session_obj.secret, id)
  local data = session_obj.serializer.serialize(session_obj.data)
  local hash = session_obj.hmac(key, concat{ id, data, session_obj.key })

  data = session_obj.cipher:encrypt(data, key, id, session_obj.key)
  return storage:save(id, expires, data, hash, close)
end

-- Calls into the underlying storage adapter to load the cookie.
-- Validates the expiry-time and hash.
-- @param session_obj (table) the session object to store the data in
-- @param cookie (string) the cookie string to open
-- @return `true` if ok, and will have set session properties; id, expires, data and present. Returns `nil` otherwise.
function regenerate.open(session_obj, cookie)
  local id, expires, data, hash = session_obj.storage:open(cookie, session_obj.cookie.lifetime)
  if id and expires and expires > time() and data and hash then
    local key = session_obj.hmac(session_obj.secret, id)
    data = session_obj.cipher:decrypt(data, key, id, session_obj.key)
    if data and session_obj.hmac(key, concat{ id, data, session_obj.key }) == hash then
      data = session_obj.serializer.deserialize(data)
      session_obj.id = id
      session_obj.expires = expires
      session_obj.data = type(data) == "table" and data or {}
      session_obj.present = true
      return true
    end
  end
end

return regenerate
