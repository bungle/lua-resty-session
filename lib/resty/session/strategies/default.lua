local type   = type
local time   = ngx.time
local concat = table.concat

local default = {}


local function update(handler, session_obj, close)
  local id = session_obj.id
  local usebefore = session_obj.usebefore
  local expires = session_obj.expires
  local storage = session_obj.storage
  local key = session_obj.hmac(session_obj.secret, id .. expires)
  local data = session_obj.serializer.serialize(session_obj.data)
  local hash = session_obj.hmac(key,
               concat{ id, usebefore, expires, data, session_obj.key })

  data = session_obj.cipher:encrypt(data, key, id, session_obj.key)
  return handler(storage, id, usebefore, expires, data, hash, close)
end

-- save the session data to the underlying storage adapter.
-- @param session_obj (table) the session object to store
-- @return result from `storage.save`.
function default.save(session_obj, close)
  return update(session_obj.storage.save, session_obj, close)
end

-- Generates a new cookie, without writing to the store.
-- Used when 'idletime' is used and 'usebefore' is altered without the content being
-- changed.
-- @param session_obj (table) the session object to store
-- @return result from `storage.save`.
function default.touch(session_obj, close)
  return update(session_obj.storage.touch, session_obj, close)
end

-- Calls into the underlying storage adapter to load the cookie.
-- Validates the expiry-time and hash.
-- @param session_obj (table) the session object to store the data in
-- @param cookie (string) the cookie string to open
-- @return `true` if ok, and will have set session properties; id, expires, data
-- and present. Returns `nil` otherwise.
function default.open(session_obj, cookie)
  local id, usebefore, expires, data, hash = session_obj.storage:open(cookie, session_obj.cookie.lifetime)
  local now = time()
  if id and
     expires and expires > now and
     usebefore and usebefore > now and
     data and hash then
    local key = session_obj.hmac(session_obj.secret, id .. expires)
    data = session_obj.cipher:decrypt(data, key, id, session_obj.key)
    if data and session_obj.hmac(key, concat{ id, usebefore, expires, data, session_obj.key }) == hash then
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

return default
