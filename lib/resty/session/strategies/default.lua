local type   = type
local time   = ngx.time
local concat = table.concat

local default = {}

function default:save(close)
  local i, e, s = self.id, self.expires, self.storage
  local k = self.hmac(self.secret, i .. e)
  local d = self.serializer.serialize(self.data)
  local h = self.hmac(k, concat{ i, e, d, self.key })
  return s:save(i, e, self.cipher:encrypt(d, k, i, self.key), h, close)
end

function default:open(cookie)
  local i, e, d, h = self.storage:open(cookie, self.cookie.lifetime)
  if i and e and e > time() and d and h then
    local k = self.hmac(self.secret, i .. e)
    d = self.cipher:decrypt(d, k, i, self.key)
    if d and self.hmac(k, concat{ i, e, d, self.key }) == h then
      d = self.serializer.deserialize(d)
      self.id = i
      self.expires = e
      self.data = type(d) == "table" and d or {}
      self.present = true
      return true
    end
  end
end

return default
