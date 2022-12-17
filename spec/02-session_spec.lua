local session = require "resty.session"

local function extract_session_cookie(cookie_name, cookies)
  local session_cookie = ngx.re.match(cookies, cookie_name .. "=([\\w-]+);")
  return session_cookie and session_cookie[1] or ""
end

describe("Session initialization: new() creates a new session", function()
  local cookie_name   = "session_cookie"
  local test_key      = "test_key"
  local data          = "test_data"
  local test_subject  = "test_subject"
  local test_audience = "test_audience"
  local configuration = {}

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
    configuration.ikm = "some_ikm"
    session.init(configuration)
    local s = session.new()
    assert.is_not_nil(s)
    test_session(s)
    assert.equals(configuration.ikm, s.meta.ikm)
  end)
end)
