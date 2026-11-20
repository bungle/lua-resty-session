---
-- Ensure to keep the tests consistent with those in 07-revocation-2_spec.lua


local session = require "resty.session"
local utils = require "resty.session.utils"


local before_each = before_each
local after_each = after_each
local lazy_setup = lazy_setup
local describe = describe
local ipairs = ipairs
local assert = assert
local sleep = ngx.sleep
local time = ngx.time
local it = it


local storage_configs = {
  file = {
    suffix = "revocation",
  },
  shm = {
    prefix = "revocations",
  },
  redis = {
    prefix = "revocations",
    password = "password",
  },
  memcached = {
    prefix = "revocations",
  },
}


local function extract_cookie(cookie_name, cookies)
  local session_cookie
  if type(cookies) == "table" then
    for _, v in ipairs(cookies) do
      session_cookie = ngx.re.match(v, cookie_name .. "=([\\w-]+);")
      if session_cookie then
        return session_cookie[1]
      end
    end
    return ""
  end
  session_cookie = ngx.re.match(cookies, cookie_name .. "=([\\w-]+);")
  return session_cookie and session_cookie[1] or ""
end


for _, st in ipairs({
  "file",
  "shm",
  "redis",
  "memcached",
}) do
  describe("Revocation tests 1", function()
    local current_time
    local store
    local long_ttl  = 60
    local short_ttl = 2
    local key       = "test_key_1iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
    local key1      = "test_key_2iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
    local key2      = "test_key_3iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
    local name      = "session_cookie"
    local mark      = "1"

    lazy_setup(function()
      local conf = {
        storage = "cookie",
        revocation = st,
      }
      conf[st] = storage_configs[st]
      store = utils.load_storage(st, conf)
      assert.is_not_nil(store)
    end)

    before_each(function()
      current_time = time()
    end)

    describe("[#" .. st .. "] revocation storage: SET + GET", function()
      after_each(function()
        store:delete(name, key, current_time)
        store:delete(name, key1, current_time)
        store:delete(name, key2, current_time)
      end)

      it("SET: stores revocation mark and GET observes it", function()
        local ok = store:set(name, key, mark, long_ttl, current_time)
        assert.is_not_nil(ok)

        local data, err = store:get(name, key, current_time)
        assert.is_nil(err)
        assert.equals(mark, data)
      end)

      it("GET: missing revocation key returns not revoked", function()
        local data, err = store:get(name, key1, current_time)
        assert.is_nil(data)
        assert.is_nil(err)
      end)

      it("SET: ttl expires revocation entry", function()
        local ok = store:set(name, key2, mark, short_ttl, current_time)
        assert.is_not_nil(ok)

        local data, err = store:get(name, key2, current_time)
        assert.is_nil(err)
        assert.equals(mark, data)

        sleep(short_ttl + 1)

        data, err = store:get(name, key2, time())
        assert.is_nil(data)
        assert.is_nil(err)
      end)

      it("SET: re-mark refreshes ttl", function()
        local ok = store:set(name, key, mark, short_ttl, current_time)
        assert.is_not_nil(ok)

        sleep(1)

        ok = store:set(name, key, mark, long_ttl, time())
        assert.is_not_nil(ok)

        sleep(short_ttl + 1)

        local data, err = store:get(name, key, time())
        assert.is_nil(err)
        assert.equals(mark, data)
      end)
    end)

    describe("[#" .. st .. "] session: revocation lifecycle", function()
      local cookie_name = "session_cookie"
      local cookie_index = 0
      local test_key    = "test_key"
      local value       = "test_data"

      local function save_session(s, cookies)
        session.__set_ngx_header(cookies)
        s:set(test_key, value)
        local ok, err = s:save()
        assert.is_true(ok)
        assert.is_nil(err)
        return extract_cookie(cookie_name, cookies["Set-Cookie"])
      end

      local function open_session(session_cookie, configuration)
        local s = session.new(configuration)
        session.__set_ngx_var({
          ["cookie_" .. cookie_name] = session_cookie,
        })

        local ok, err = s:open()
        if not ok then
          return nil, err
        end

        return s
      end

      before_each(function()
        -- Lineage marks share the worker cache across session instances.
        cookie_index = cookie_index + 1
        cookie_name = "session_cookie_" .. st .. "_" .. cookie_index
        local conf = {
          cookie_name = cookie_name,
          storage = "cookie",
          revocation = st,
        }
        conf[st] = storage_configs[st]
        session.init(conf)
      end)

      it("open succeeds for a valid session with revocation enabled", function()
        local cookies = {}
        local s = session.new()
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        assert.equals(value, s2:get(test_key))
        s2:close()
      end)

      it("destroy: rejected cookie cannot be reopened", function()
        local cookies = {}
        local s = session.new()
        local session_cookie = save_session(s, cookies)
        assert.is_not_equal("", session_cookie)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        assert.equals(value, s2:get(test_key))

        session.__set_ngx_header(cookies)
        local ok
        ok, err = s2:destroy()
        assert.is_true(ok)
        assert.is_nil(err)

        local s3
        s3, err = open_session(session_cookie)
        assert.is_nil(s3)
        assert.equals("session revoked", err)
      end)

      it("save rotation does not revoke the previous cookie", function()
        local cookies = {}
        local s = session.new()
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)

        s2:set(test_key, "rotated")
        session.__set_ngx_header(cookies)
        local ok
        ok, err = s2:save()
        assert.is_true(ok)
        assert.is_nil(err)
        s2:close()

        local s3
        s3, err = open_session(session_cookie)
        assert.is_not_nil(s3)
        assert.is_nil(err)
        assert.equals(value, s3:get(test_key))
        s3:close()
      end)
    end)
  end)
end


describe("Revocation tests 1 session: configuration", function()
  local cookie_name = "session_cookie"

  it("cookie session without revocation remains usable after destroy", function()
    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
    })

    local cookies = {}
    local s = session.new()
    session.__set_ngx_header(cookies)
    s:set("test_key", "test_data")
    local ok, err = s:save()
    assert.is_true(ok)
    assert.is_nil(err)
    local session_cookie = extract_cookie(cookie_name, cookies["Set-Cookie"])
    s:close()

    session.__set_ngx_var({
      ["cookie_" .. cookie_name] = session_cookie,
    })
    local s2 = session.new()
    ok, err = s2:open()
    assert.is_true(ok)
    assert.is_nil(err)

    session.__set_ngx_header(cookies)
    ok, err = s2:destroy()
    assert.is_true(ok)
    assert.is_nil(err)

    session.__set_ngx_var({
      ["cookie_" .. cookie_name] = session_cookie,
    })
    local s3 = session.new()
    ok, err = s3:open()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.is_not_equal("session revoked", err)
  end)

  it("skips revocation when storage backend is configured", function()
    session.init({
      cookie_name = cookie_name,
      storage = "redis",
      revocation = "shm",
      redis = {
        prefix = "sessions",
        password = "password",
      },
      shm = {
        prefix = "revocations",
      },
    })

    local s = session.new()
    assert.is_nil(s.revocation)
  end)

  it("does not infer revocation storage from backend configuration", function()
    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      redis = {
        host = "127.0.0.1",
        password = "password",
      },
    })

    local s = session.new()
    assert.is_nil(s.revocation)
  end)

  it("skips revocation when revocation is explicitly false", function()
    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      redis = {
        host = "127.0.0.1",
        password = "password",
      },
      revocation = false,
    })

    local s = session.new()
    assert.is_nil(s.revocation)
  end)
end)


describe("session: revocation cache", function()
  local cookie_name = "session_cookie"
  local session_cookie
  local cookies
  local get_count
  local set_count
  local revoked
  local store

  local function open_session()
    session.__set_ngx_var({
      ["cookie_" .. cookie_name] = session_cookie,
    })

    local s = session.new()
    local ok, err = s:open()
    return s, ok, err
  end

  local fake_stores = 0

  local function initialize(cache_ttl)
    get_count = 0
    set_count = 0
    revoked = false
    fake_stores = fake_stores + 1
    store = {
      name = "fake-store-" .. fake_stores,
      get = function()
        get_count = get_count + 1
        return revoked and "1" or nil
      end,
      set = function()
        set_count = set_count + 1
        revoked = true
        return true
      end,
    }

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_cache_ttl = cache_ttl,
    })

    cookies = {}
    session.__set_ngx_header(cookies)
    local s = session.new()
    s:set("test_key", "test_data")
    local ok, err = s:save()
    assert.is_true(ok)
    assert.is_nil(err)
    session_cookie = extract_cookie(cookie_name, cookies["Set-Cookie"])
    s:close()
  end

  before_each(function()
    initialize(5)
  end)

  it("reuses a cached revocation lookup", function()
    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    s:close()

    s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(2, get_count)
    s:close()
  end)

  it("updates the cache after revoking a session", function()
    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)

    session.__set_ngx_header(cookies)
    ok, err = s:destroy()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(2, set_count)

    local reopened
    reopened, ok, err = open_session()
    assert.is_nil(ok)
    assert.equals("session revoked", err)
    assert.equals(2, get_count)
    reopened:close()
  end)

  it("queries the revocation store after the cache entry expires", function()
    initialize(1)

    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    s:close()

    sleep(2)

    s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(4, get_count)
    s:close()
  end)

  it("can disable the revocation cache", function()
    initialize(0)

    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    s:close()

    s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(4, get_count)
    s:close()
  end)

  it("caches an open fail-mode result when the store is unreachable", function()
    get_count = 0
    store = {
      get = function()
        get_count = get_count + 1
        return nil, "connection refused"
      end,
      set = function()
        return true
      end,
    }

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = "open",
      revocation_error_cache_ttl = 5,
    })

    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    s:close()

    s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(2, get_count)
    s:close()
  end)

  it("caches a closed fail-mode result when the store is unreachable", function()
    get_count = 0
    store = {
      get = function()
        get_count = get_count + 1
        return nil, "connection refused"
      end,
      set = function()
        return true
      end,
    }

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = "closed",
      revocation_error_cache_ttl = 5,
    })

    local s, ok, err = open_session()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    s:close()

    s, ok, err = open_session()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    assert.equals(1, get_count)
    s:close()
  end)

  it("does not reuse a cached open fail-mode error under a closed fail mode", function()
    get_count = 0
    store = {
      get = function()
        get_count = get_count + 1
        return nil, "connection refused"
      end,
      set = function()
        return true
      end,
    }

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = "open",
      revocation_error_cache_ttl = 5,
    })

    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)
    s:close()

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = "closed",
      revocation_error_cache_ttl = 5,
    })

    s, ok, err = open_session()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    assert.equals(3, get_count)
    s:close()

    -- each policy still caches its own interpretation of the error
    s, ok, err = open_session()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    assert.equals(3, get_count)
    s:close()
  end)

  it("skips the session id write when it is already revoked", function()
    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)

    local other, ook, oerr = open_session()
    assert.is_true(ook)
    assert.is_nil(oerr)
    assert.equals(2, get_count)

    session.__set_ngx_header(cookies)
    ok, err = s:destroy()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(2, set_count)

    session.__set_ngx_header(cookies)
    ook, oerr = other:destroy()
    assert.is_true(ook)
    assert.is_nil(oerr)
    assert.equals(2, get_count)
    -- the lineage mark is written again, without a lookup first
    assert.equals(3, set_count)
  end)

  it("caches a failed revocation write for later lookups", function()
    get_count = 0
    set_count = 0
    store = {
      get = function()
        get_count = get_count + 1
        return nil
      end,
      set = function()
        set_count = set_count + 1
        return nil, "connection refused"
      end,
    }

    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = "closed",
      revocation_error_cache_ttl = 5,
    })

    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)

    session.__set_ngx_header(cookies)
    ok, err = s:destroy()
    assert.is_nil(ok)
    assert.matches("unable to mark session revoked", err)
    assert.equals(1, set_count)

    ok, err = s:destroy()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    assert.equals(1, set_count)

    local reopened
    reopened, ok, err = open_session()
    assert.is_nil(ok)
    assert.matches("unable to check session revocation", err)
    assert.equals(2, get_count)
    reopened:close()
  end)
end)


describe("session: revocation lineage", function()
  local cookie_name = "lineage_cookie"
  local marks
  local ttls
  local fail_lineage_writes

  local store = {
    get = function(_, _, key)
      return marks[key]
    end,
    set = function(_, _, key, value, ttl)
      -- session id marks carry "1"; lineage marks carry the time they were written
      if fail_lineage_writes and value ~= "1" then
        return nil, "connection refused"
      end
      marks[key] = value
      ttls[key] = ttl
      return true
    end,
  }

  local function initialize(fail_mode)
    marks = {}
    ttls = {}
    fail_lineage_writes = false
    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = store,
      revocation_fail_mode = fail_mode,
      revocation_cache_ttl = 0,
      revocation_error_cache_ttl = 0,
    })
  end

  local function login()
    local cookies = {}
    session.__set_ngx_header(cookies)
    local s = session.new()
    s:set("test_key", "test_data")
    local ok, err = s:save()
    assert.is_true(ok)
    assert.is_nil(err)
    return extract_cookie(cookie_name, cookies["Set-Cookie"])
  end

  local function open(cookie)
    session.__set_ngx_var({
      ["cookie_" .. cookie_name] = cookie,
    })
    local s = session.new()
    local ok, err = s:open()
    return s, ok, err
  end

  -- what a refresh does to a cookie: open it and save it under a new session id
  local function rotate(cookie)
    local s, ok, err = open(cookie)
    assert.is_true(ok)
    assert.is_nil(err)
    local cookies = {}
    session.__set_ngx_header(cookies)
    ok, err = s:save()
    assert.is_true(ok)
    assert.is_nil(err)
    local rotated = extract_cookie(cookie_name, cookies["Set-Cookie"])
    assert.not_equals(cookie, rotated)
    return rotated
  end

  local function destroy(cookie)
    local s, ok, err = open(cookie)
    assert.is_true(ok)
    assert.is_nil(err)
    session.__set_ngx_header({})
    return s:destroy()
  end

  it("revokes the whole lineage whichever cookie of it is presented at logout", function()
    -- a chain of rotations plus a fork made from the original cookie
    local names = { "original", "rotated", "rotated again", "forked from original" }

    for logout_index = 1, #names do
      initialize("closed")

      local original = login()
      local rotated = rotate(original)
      local cookies = {
        original,
        rotated,
        rotate(rotated),
        rotate(original),
      }

      local ok, err = destroy(cookies[logout_index])
      assert.is_true(ok, "logout with the " .. names[logout_index] .. " cookie")
      assert.is_nil(err)

      for index, cookie in ipairs(cookies) do
        local s, opened, oerr = open(cookie)
        assert.is_nil(opened, names[index] .. " cookie after logout with the "
                              .. names[logout_index] .. " cookie")
        assert.equals("session revoked", oerr)
        s:close()
      end

      -- a different login is not part of the lineage
      local other = login()
      local s, opened, oerr = open(other)
      assert.is_true(opened)
      assert.is_nil(oerr)
      s:close()
    end
  end)

  it("revokes cookies rotated from a revoked cookie after the logout", function()
    initialize("closed")

    local original = login()
    local s, ok, err = open(original)
    assert.is_true(ok)
    assert.is_nil(err)

    -- the attacker holds an open session while the user logs out
    local cookies = {}
    session.__set_ngx_header(cookies)
    ok, err = destroy(rotate(original))
    assert.is_true(ok)
    assert.is_nil(err)

    session.__set_ngx_header(cookies)
    s:save()
    local late = extract_cookie(cookie_name, cookies["Set-Cookie"])
    local opened, oerr
    s, opened, oerr = open(late)
    assert.is_nil(opened)
    assert.equals("session revoked", oerr)
    s:close()
  end)

  it("keeps another login usable when one login logs out", function()
    initialize("closed")

    local first = login()
    local second = login()
    assert.is_true(destroy(first))

    local s, opened, err = open(second)
    assert.is_true(opened)
    assert.is_nil(err)
    s:close()
  end)

  it("keeps the lineage mark for a full rolling window", function()
    initialize("closed")

    local ok = destroy(login())
    assert.is_true(ok)

    local lineage_ttl
    for key, value in pairs(marks) do
      if value ~= "1" then
        lineage_ttl = ttls[key]
      end
    end

    -- a full default rolling window plus the stale ttl, shorter than what is left
    -- of the absolute timeout: a cookie saved right before the logout is covered
    assert.equals(3600 + 10, lineage_ttl)
  end)

  it("rejects the logout when the lineage mark cannot be written and the fail mode is closed", function()
    initialize("closed")

    local cookie = login()
    fail_lineage_writes = true

    local ok, err = destroy(cookie)
    assert.is_nil(ok)
    assert.matches("unable to mark session revoked", err)
  end)

  it("does not add a lineage id when revocation is disabled", function()
    session.init({
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = false,
    })

    local cookie = login()
    local s, ok = open(cookie)
    assert.is_true(ok)
    -- the lineage id is the fourth field of the payload entry
    assert.is_nil(s.data[s.data_index][4])
    s:close()
  end)
end)


describe("session: revocation cache with a named backend", function()
  local cookie_name = "named_backend_cookie"
  local gets

  before_each(function()
    gets = 0
    -- a named backend is instantiated again by every session.new
    package.loaded["counting-revocation"] = {
      new = function()
        return {
          get = function()
            gets = gets + 1
          end,
          set = function()
            return true
          end,
        }
      end,
    }
    session.init({ cookie_name = cookie_name, storage = "cookie" })
  end)

  -- a new table on every call, like a caller that builds its configuration per request
  local function configuration(host)
    return {
      cookie_name = cookie_name,
      storage = "cookie",
      revocation = "counting-revocation",
      ["counting-revocation"] = { host = host },
    }
  end

  local function login(host)
    local cookies = {}
    session.__set_ngx_header(cookies)
    local s = session.new(configuration(host))
    s:set("test_key", "test_data")
    assert.is_true(s:save())
    return extract_cookie(cookie_name, cookies["Set-Cookie"])
  end

  local function open(cookie, host)
    session.__set_ngx_var({ ["cookie_" .. cookie_name] = cookie })
    local s = session.new(configuration(host))
    local ok, err = s:open()
    s:close()
    return ok, err
  end

  it("shares cache entries between sessions given equal backend settings", function()
    local cookie = login("redis-a")

    for _ = 1, 3 do
      assert.is_true(open(cookie, "redis-a"))
    end

    -- the session id and its lineage are each looked up once
    assert.equals(2, gets)
  end)

  it("does not share cache entries between different backend settings", function()
    local cookie = login("redis-a")

    assert.is_true(open(cookie, "redis-a"))
    assert.equals(2, gets)

    assert.is_true(open(cookie, "redis-b"))
    assert.equals(4, gets)
  end)
end)
