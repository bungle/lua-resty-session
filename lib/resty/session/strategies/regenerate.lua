local type   = type
local time   = ngx.time
local concat = table.concat

local regenerate = {}

-- save the session data to the underlying storage adapter.
-- @param session_obj (table) the session object to store
-- @return result from `storage.save`.
function regenerate.save(session_obj, close)
  local id = session_obj.id
  local usebefore = session_obj.usebefore
  local expires = session_obj.expires
  local storage = session_obj.storage

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
  local hash = session_obj.hmac(key, concat{ id, usebefore, data, session_obj.key })

  data = session_obj.cipher:encrypt(data, key, id, session_obj.key)
  return storage:save(id, usebefore, expires, data, hash, close)
end

-- Touch the session, updates the usebefore. Without writing to the store.
-- @param session_obj (table) the session object to store
-- @return result from `storage.save`.
function regenerate.touch(session_obj, close)
  local id = session_obj.id
  local usebefore = session_obj.usebefore
  local expires = session_obj.expires
  local storage = session_obj.storage

  local key = session_obj.hmac(session_obj.secret, id)
  local data = session_obj.serializer.serialize(session_obj.data)
  local hash = session_obj.hmac(key, concat{ id, usebefore, data, session_obj.key })

  data = session_obj.cipher:encrypt(data, key, id, session_obj.key)
  return storage:touch(id, usebefore, expires, data, hash, close)
end

-- Calls into the underlying storage adapter to load the cookie.
-- Validates the expiry-time and hash.
-- @param session_obj (table) the session object to store the data in
-- @param cookie (string) the cookie string to open
-- @return `true` if ok, and will have set session properties; id, usebefore,
-- expires, data and present. Returns `nil` otherwise.
function regenerate.open(session_obj, cookie)
  local id, usebefore, expires, data, hash = session_obj.storage:open(cookie)
  local now = time()
  if id and
     expires and expires > now and
     usebefore and usebefore > now and
     data and hash then
    local key = session_obj.hmac(session_obj.secret, id)
    data = session_obj.cipher:decrypt(data, key, id, session_obj.key)
    if data and session_obj.hmac(key, concat{ id, usebefore, data, session_obj.key }) == hash then
      data = session_obj.serializer.deserialize(data)
      session_obj.id = id
      session_obj.usebefore = usebefore
      session_obj.expires = expires
      session_obj.data = type(data) == "table" and data or {}
      session_obj.present = true
      return true
    end
  end
end

return regenerate
