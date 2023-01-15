local session = require "resty.session"

local function extract_session_cookie(cookie_name, cookies)
  local session_cookie = ngx.re.match(cookies, cookie_name .. "=([\\w-]+);")
  return session_cookie and session_cookie[1] or ""
end
describe("Session", function()
  local configuration = {}

  describe("instance methods behave as expected", function()
    local cookie_name   = "session_cookie"
    local test_key      = "test_key"
    local data          = "test_data"
    local test_subject  = "test_subject"
    local test_audience = "test_audience"

    local function test_session_set_get(s)
      assert.is_nil(
        s:get(test_key)      or
        s:get(test_subject)  or
        s:get(test_audience)
      )

      s:set(test_key, data)
      s:set_subject(test_subject)
      s:set_audience(test_audience)
      assert.equals(s:get(test_key), data)
      assert.equals(s:get_subject(), test_subject)
      assert.equals(s:get_audience(), test_audience)
    end

    local function test_session_save(s, cookies)
      session.__set_ngx_header(cookies)
      local ok, err = s:save()
      assert.equals(s.state, "open")
      assert.is_true(ok)
      assert.is_nil(err)
      assert.is_not_nil(s.meta)
      assert.is_not_nil(s.meta.data_size)
      assert(s.meta.data_size > 0)
      local session_cookie = extract_session_cookie(cookie_name, cookies["Set-Cookie"])
      return session_cookie
    end

    local function test_session_close_open(s, session_cookie)
      s:close()
      assert.equals(s.state, "closed")

      local ok, err = pcall(s.get, s, "anything")
      assert.is_false(ok)
      assert.matches("unable to get session data on closed session", err)

      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie
      })
      ok, err = s:open()
      assert.is_true(ok)
      assert.is_nil(err)
      assert.equals(s.state, "open")
      assert.equals(data, s:get(test_key))
    end

    local function test_session_touch(s)
       local ok, err = s:touch()
       assert.is_true(ok)
       assert.is_nil(err)
       assert.equals(s.state, "open")
    end

    local function test_session_destroy_open(s)
      local cookies = {}
      session.__set_ngx_header(cookies)
      local ok, err = s:destroy()
      assert.is_true(ok)
      assert.is_nil(err)
      assert.equals(s.state, "closed")
      ok, err = pcall(s.get, s, "anything")
      assert.is_false(ok)
      assert.matches("unable to get session data on closed session", err)
      local session_cookie = extract_session_cookie(cookie_name, cookies["Set-Cookie"]) -- empty

      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie
      })
      ok, err = s:open()
      assert.is_nil(ok)
      assert.equals("invalid session header", err)
      assert.equals(s.state, "closed")
      ok, err = pcall(s.get, s, "anything")
      assert.is_false(ok)
      assert.matches("unable to get session data on closed session", err)
    end

    local function test_session(s)
      local session_cookie
      local cookies = {}

      test_session_set_get(s)
      session_cookie = test_session_save(s, cookies)
      test_session_close_open(s, session_cookie)
      test_session_touch(s)
      test_session_destroy_open(s)
    end

    before_each(function()
      configuration = {
        cookie_name = cookie_name
      }
    end)

    it("with default values", function()
      session.init(configuration)
      local s = session.new()
      assert.is_not_nil(s)
      test_session(s)
    end)

    it("with custom secret", function()
      configuration.secret = "t"
      session.init(configuration)
      local s = session.new()
      assert.is_not_nil(s)
      test_session(s)
    end)

    it("custom ikm takes precedence on secret", function()
      configuration.secret = "t"
      configuration.ikm = "00000000000000000000000000000000"
      session.init(configuration)
      local s = session.new()
      assert.is_not_nil(s)
      test_session(s)
      assert.equals(configuration.ikm, s.meta.ikm)
    end)
  end)

  describe("Fields validation", function()
    describe("init validates fields", function()
      before_each(function()
        configuration = {}
      end)

      it("custom ikm must be 32 bytes", function()
        configuration.ikm = "12345"
        local ok, err = pcall(session.init,configuration)
        assert.is_false(ok)
        assert.matches("ikm field has invalid size", err)
      end)

      it("custom ikm_fallbacks must be 32 bytes", function()
        configuration.ikm_fallbacks = {
          "00000000000000000000000000000000",
          "123456",
        }
        local ok, err = pcall(session.init,configuration)
        assert.is_false(ok)
        assert.matches("ikm_fallbacks field has invalid size", err)
      end)
    end)

    describe("new validates fields", function()
      before_each(function()
        configuration = {}
      end)

      it("custom ikm must be 32 bytes", function()
        configuration.ikm = "12345"
        local ok, err = pcall(session.new, configuration)
        assert.is_false(ok)
        assert.matches("ikm field has invalid size", err)
      end)

      it("custom ikm_fallbacks must be 32 bytes", function()
        configuration.ikm_fallbacks = {
          "00000000000000000000000000000000",
          "123456",
        }
        local ok, err = pcall(session.new, configuration)
        assert.is_false(ok)
        assert.matches("ikm_fallbacks field has invalid size", err)
      end)
    end)
  end)
end)
