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

      local function subject_mark_key(subject)
        local s = session.new()
        return s.hash_storage_key("subject:" .. s.hash_subject(subject))
      end

      local function sid_mark_key(sid)
        return session.new().hash_storage_key("sid:" .. sid)
      end

      local subjects = { "test", "legacy", "other", "aud-a" }
      local sids = { "test" }

      before_each(function()
        -- Subject and sid marks share the worker cache across session instances.
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

      after_each(function()
        for _, subject in ipairs(subjects) do
          store:delete(cookie_name, subject_mark_key(subject), time())
        end
        for _, sid in ipairs(sids) do
          store:delete(cookie_name, sid_mark_key(sid), time())
        end
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

      it("revoke_subject: session carrying a revoked key cannot be reopened", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        assert.is_true(session.revoke_subject("test", long_ttl))

        local s2, err = open_session(session_cookie)
        assert.is_nil(s2)
        assert.equals("session revoked", err)
      end)

      it("revoke_subject: session created after the revocation opens", function()
        assert.is_true(session.revoke_subject("test", long_ttl))
        sleep(1)

        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        s2:close()
      end)

      for _, kind in ipairs({ "subject", "sid" }) do
        it("revoke_" .. kind .. ": replaces a cached miss and preserves later sessions", function()
          local cookies = {}
          local s = session.new()
          s["set_" .. kind](s, "test")
          local old_cookie = save_session(s, cookies)
          s:close()

          local old, err = open_session(old_cookie)
          assert.is_not_nil(old)
          assert.is_nil(err)
          old:close()

          assert.is_true(session["revoke_" .. kind]("test", long_ttl))
          old, err = open_session(old_cookie)
          assert.is_nil(old)
          assert.equals("session revoked", err)

          sleep(1)
          local fresh = session.new()
          fresh["set_" .. kind](fresh, "test")
          local new_cookie = save_session(fresh, {})
          fresh:close()

          fresh, err = open_session(new_cookie)
          assert.is_not_nil(fresh)
          assert.is_nil(err)
          fresh:close()

          old, err = open_session(old_cookie)
          assert.is_nil(old)
          assert.equals("session revoked", err)
        end)

        it("revoke_" .. kind .. ": caches the store timestamp instead of a session-specific result", function()
          local s = session.new()
          s["set_" .. kind](s, "test")
          local old_cookie = save_session(s, {})
          local revoked_at = time()
          s:close()

          sleep(1)
          local fresh = session.new()
          fresh["set_" .. kind](fresh, "test")
          local new_cookie = save_session(fresh, {})
          fresh:close()

          local key = kind == "subject" and subject_mark_key("test") or sid_mark_key("test")
          assert.is_not_nil(store:set(cookie_name, key, tostring(revoked_at), long_ttl, time()))

          local err
          fresh, err = open_session(new_cookie)
          assert.is_not_nil(fresh)
          assert.is_nil(err)
          fresh:close()

          local old
          old, err = open_session(old_cookie)
          assert.is_nil(old)
          assert.equals("session revoked", err)
        end)
      end

      it("revoke_subject: re-login after a revoked open gets a fresh session", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        assert.is_true(session.revoke_subject("test", long_ttl))

        session.__set_ngx_var({
          ["cookie_" .. cookie_name] = session_cookie,
        })
        local s2, err, exists = session.open()
        assert.equals("session revoked", err)
        assert.is_false(exists)

        sleep(1)
        s2:set_subject("test")
        session_cookie = save_session(s2, cookies)
        s2:close()

        local s3
        s3, err = open_session(session_cookie)
        assert.is_not_nil(s3)
        assert.is_nil(err)
        s3:close()
      end)

      it("revoke_subject: remember cookie carrying a revoked audience is not restored", function()
        local conf = {
          cookie_name = cookie_name,
          storage = "cookie",
          revocation = st,
          remember = true,
        }
        conf[st] = storage_configs[st]
        session.init(conf)

        local cookies = {}
        local a = session.new({ audience = "a" })
        a:set_remember(true)
        a:set_subject("aud-a")
        local session_cookie = save_session(a, cookies)
        local remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        a:close()

        session.__set_ngx_var({
          ["cookie_" .. cookie_name] = session_cookie,
          ["cookie_remember"] = remember_cookie,
        })
        local b, err = session.open({ audience = "b" })
        assert.equals("missing session audience", err)
        b:set_remember(true)
        cookies = {}
        save_session(b, cookies)
        remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        assert.is_not_equal("", remember_cookie)
        b:close()

        assert.is_true(session.revoke_subject("aud-a", long_ttl))

        session.__set_ngx_header(cookies)
        session.__set_ngx_var({
          ["cookie_remember"] = remember_cookie,
        })
        local b2 = session.new({ audience = "b" })
        local ok = b2:open()
        assert.is_nil(ok)
      end)

      it("revoke_subject: remember cookie with a revoked audience is not restored for a new audience", function()
        local conf = {
          cookie_name = cookie_name,
          storage = "cookie",
          revocation = st,
          remember = true,
        }
        conf[st] = storage_configs[st]
        session.init(conf)

        local cookies = {}
        local a = session.new({ audience = "a" })
        a:set_remember(true)
        a:set_subject("aud-a")
        save_session(a, cookies)
        local remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        a:close()

        assert.is_true(session.revoke_subject("aud-a", long_ttl))

        session.__set_ngx_var({
          ["cookie_remember"] = remember_cookie,
        })
        local b, err = session.open({ audience = "b" })
        assert.is_not_nil(err)
        cookies = {}
        local session_cookie = save_session(b, cookies)
        b:close()

        local a2
        a2, err = open_session(session_cookie, { audience = "a" })
        assert.is_nil(a2)
        assert.equals("missing session audience", err)
      end)

      it("revoke_subject: re-login after revocation issues a fresh remember cookie", function()
        local conf = {
          cookie_name = cookie_name,
          storage = "cookie",
          revocation = st,
          remember = true,
        }
        conf[st] = storage_configs[st]
        session.init(conf)

        local cookies = {}
        local s = session.new()
        s:set_remember(true)
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        local remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        s:close()

        assert.is_true(session.revoke_subject("test", long_ttl))
        sleep(1)

        session.__set_ngx_var({
          ["cookie_" .. cookie_name] = session_cookie,
          ["cookie_remember"] = remember_cookie,
        })
        local s2, err = session.open()
        assert.equals("session revoked", err)

        s2:set_remember(true)
        s2:set_subject("test")
        cookies = {}
        save_session(s2, cookies)
        remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        assert.is_not_equal("", remember_cookie)
        s2:close()

        session.__set_ngx_header(cookies)
        session.__set_ngx_var({
          ["cookie_remember"] = remember_cookie,
        })
        local s3 = session.new()
        local ok, err = s3:open()
        assert.is_true(ok)
        assert.is_nil(err)
        s3:close()
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

      it("sid: round-trip through the cookie without a subject", function()
        local cookies = {}
        local s = session.new()
        s:set_sid("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        assert.equals("test", s2:get_sid())
        assert.is_nil(s2:get_subject())
        s2:close()
      end)

      it("revoke_sid: session carrying a revoked sid cannot be reopened", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("other")
        s:set_sid("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        assert.is_true(session.revoke_sid("test", long_ttl))

        local s2, err = open_session(session_cookie)
        assert.is_nil(s2)
        assert.equals("session revoked", err)
      end)

      it("revoke_sid: does not revoke a session whose subject matches the sid", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        assert.is_true(session.revoke_sid("test", long_ttl))

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        s2:close()
      end)

      it("subject mark: mark at or after creation revokes", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        local ok = store:set(cookie_name, subject_mark_key("test"), tostring(time()), long_ttl, time())
        assert.is_not_nil(ok)

        local s2, err = open_session(session_cookie)
        assert.is_nil(s2)
        assert.equals("session revoked", err)
      end)

      it("subject mark: mark before creation does not revoke", function()
        local ok = store:set(cookie_name, subject_mark_key("test"), tostring(time() - 1), long_ttl, time())
        assert.is_not_nil(ok)

        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        assert.equals(value, s2:get(test_key))
        s2:close()
      end)

      it("subject mark: legacy mark revokes regardless of time", function()
        local ok = store:set(cookie_name, subject_mark_key("legacy"), "1", long_ttl, time())
        assert.is_not_nil(ok)

        local cookies = {}
        local s = session.new()
        s:set_subject("legacy")
        local session_cookie = save_session(s, cookies)
        s:close()

        local s2, err = open_session(session_cookie)
        assert.is_nil(s2)
        assert.equals("session revoked", err)
      end)

      it("subject mark: mark for another key does not revoke", function()
        local cookies = {}
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, cookies)
        s:close()

        local ok = store:set(cookie_name, subject_mark_key("other"), tostring(time()), long_ttl, time())
        assert.is_not_nil(ok)

        local s2, err = open_session(session_cookie)
        assert.is_not_nil(s2)
        assert.is_nil(err)
        assert.equals(value, s2:get(test_key))
        s2:close()
      end)

      it("subject mark: are scoped to the audience", function()
        local cookies = {}
        local s = session.new({ audience = "a" })
        s:set_subject("aud-a")
        local session_cookie = save_session(s, cookies)
        s:close()

        session.__set_ngx_var({
          ["cookie_" .. cookie_name] = session_cookie,
        })
        local s2, err, exists = session.open({ audience = "b" })
        assert.is_false(exists)
        assert.equals("missing session audience", err)

        local both_audiences_cookie = save_session(s2, cookies)
        s2:close()

        local ok = store:set(cookie_name, subject_mark_key("aud-a"), tostring(time()), long_ttl, time())
        assert.is_not_nil(ok)

        local sb, err_b = open_session(both_audiences_cookie, { audience = "b" })
        assert.is_not_nil(sb)
        assert.is_nil(err_b)
        sb:close()

        local sa, err_a = open_session(both_audiences_cookie, { audience = "a" })
        assert.is_nil(sa)
        assert.equals("session revoked", err_a)
      end)

      it("subject mark: revoke a remembered session with the cache disabled", function()
        local conf = {
          cookie_name = cookie_name,
          storage = "cookie",
          revocation = st,
          revocation_cache_ttl = 0,
          remember = true,
        }
        conf[st] = storage_configs[st]
        session.init(conf)

        local cookies = {}
        local s = session.new()
        s:set_remember(true)
        s:set_subject("test")
        save_session(s, cookies)
        local remember_cookie = extract_cookie("remember", cookies["Set-Cookie"])
        assert.is_not_equal("", remember_cookie)
        s:close()

        session.__set_ngx_header(cookies)
        session.__set_ngx_var({
          ["cookie_remember"] = remember_cookie,
        })
        local s2 = session.new()
        local ok, err = s2:open()
        assert.is_true(ok)
        assert.is_nil(err)
        s2:close()

        local mark_ok = store:set(cookie_name, subject_mark_key("test"), tostring(time()), long_ttl, time())
        assert.is_not_nil(mark_ok)

        session.__set_ngx_header(cookies)
        session.__set_ngx_var({
          ["cookie_remember"] = remember_cookie,
        })
        local s3 = session.new()
        local ok3 = s3:open()
        assert.is_nil(ok3)
      end)

      it("subject mark: observes an external revocation after the cached miss expires", function()
        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, {})
        s:close()

        local conf = { revocation_cache_ttl = 1 }
        local opened, err = open_session(session_cookie, conf)
        assert.is_not_nil(opened)
        assert.is_nil(err)
        opened:close()

        assert.is_not_nil(store:set(cookie_name, subject_mark_key("test"), tostring(time()), long_ttl, time()))
        opened, err = open_session(session_cookie, conf)
        assert.is_not_nil(opened)
        assert.is_nil(err)
        opened:close()

        sleep(2)
        opened, err = open_session(session_cookie, conf)
        assert.is_nil(opened)
        assert.equals("session revoked", err)
      end)

      it("subject mark: isolates caches for different revocation stores", function()
        local conf = { revocation = st }
        conf[st] = {
          prefix = "other_revocations",
          suffix = "other_revocation",
          password = "password",
        }
        local other_store = assert(utils.load_storage(st, conf))
        local other_conf = { revocation = other_store }

        local s = session.new()
        s:set_subject("test")
        local session_cookie = save_session(s, {})
        s:close()

        local opened, err = open_session(session_cookie)
        assert.is_not_nil(opened)
        assert.is_nil(err)
        opened:close()

        assert.is_true(session.revoke_subject("test", long_ttl, other_conf))
        opened, err = open_session(session_cookie)
        assert.is_not_nil(opened)
        assert.is_nil(err)
        opened:close()

        opened, err = open_session(session_cookie, other_conf)
        other_store:delete(cookie_name, subject_mark_key("test"), time())
        assert.is_nil(opened)
        assert.equals("session revoked", err)
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

  local function initialize(cache_ttl)
    get_count = 0
    set_count = 0
    revoked = false
    store = {
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
    assert.equals(1, get_count)
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
    assert.equals(1, set_count)

    local reopened
    reopened, ok, err = open_session()
    assert.is_nil(ok)
    assert.equals("session revoked", err)
    assert.equals(1, get_count)
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
    assert.equals(2, get_count)
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
    assert.equals(2, get_count)
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
    assert.equals(1, get_count)
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

  it("skips the revocation write when the lookup is already revoked", function()
    local s, ok, err = open_session()
    assert.is_true(ok)
    assert.is_nil(err)

    local other, ook, oerr = open_session()
    assert.is_true(ook)
    assert.is_nil(oerr)
    assert.equals(1, get_count)

    session.__set_ngx_header(cookies)
    ok, err = s:destroy()
    assert.is_true(ok)
    assert.is_nil(err)
    assert.equals(1, set_count)

    session.__set_ngx_header(cookies)
    ook, oerr = other:destroy()
    assert.is_true(ook)
    assert.is_nil(oerr)
    assert.equals(1, get_count)
    assert.equals(1, set_count)
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
    assert.equals(1, get_count)
    reopened:close()
  end)
end)
