local utils = require "resty.session.utils"


local storage_configs = {
  file = {
    suffix = "session",
  },
  shm = {
    prefix = "sessions",
    connect_timeout = 10000,
    send_timeout = 10000,
    read_timeout = 10000,
  }
}


describe("Storage tests 1", function()
  local storage
  for _, st in ipairs({
    "file",
    "shm"
  }) do

    lazy_setup(function()
      local conf = {
        remember = true,
        store_metadata = true,
        secret = "doge1",
        secret_fallbacks = {
          "cat",
          "doge",
        },
      }
      conf[st] = storage_configs[st]
      storage = utils.load_storage(st, conf)
      assert.is_not_nil(storage)
    end)

    describe("SET + GET", function()

      local key = "test_key"
      local old_key = "old_test_key"
      local name  = "test_name"
      local value = "test_value"

      after_each(function()
        storage:delete(name, key)
      end)

      it("SET: simple set does not return errors, GET fetches value correctly", function()
        local current_time = ngx.time()
        local ttl   = 60

        local ok, err = storage:set(name, key, value, ttl, current_time)
        assert.is_not_nil(ok)
        assert.is_nil(err)

        local v, err = storage:get(name, key, current_time)
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with metadata and remember works correctly", function()
        local current_time = ngx.time()
        local ttl   = 60

        local metadata = {
          audiences = { "foo", "bar" },
          subjects  = { "tom", "jerry" },
        }

        local ok = storage:set(name, key, value, ttl, current_time, nil, nil, metadata, true)
        assert.is_not_nil(ok)
        -- TODO check that metadata is also stored
        local v, err = storage:get(name, key, current_time)
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with old_key correctly applies stale ttl on old key", function()
        local ttl   = 60
        local current_time = ngx.time()
        local stale_ttl = 1

        local ok, err = storage:set(name, old_key, value, ttl, current_time)
        assert.is_not_nil(ok)
        assert.is_nil(err)

        ok = storage:set(name, key, value, ttl, current_time, old_key, stale_ttl, nil, false)
        assert.is_not_nil(ok)

        ngx.sleep(3)

        local v = storage:get(name, old_key, current_time)
        assert.is_nil(v)
      end)

      it("SET: ttl works as expected", function()
        local ttl = 1
        local current_time = ngx.time()

        local ok, err = storage:set(name, key, value, ttl, current_time)
        assert.is_not_nil(ok)
        assert.is_nil(err)

        ngx.sleep(3)
        current_time = ngx.time()

        local v = storage:get(name, key, current_time)
        assert.is_nil(v)
      end)
    end)

    describe("DELETE", function()
      local name  = "test_name"
      local key   = "test_key"
      local value = "test_value"

      it("deleted file is not found", function()
        local ttl   = 1
        local current_time = ngx.time()

        local ok, err = storage:set(name, key, value, ttl, current_time)
        assert.is_not_nil(ok)
        assert.is_nil(err)

        storage:delete(name, key)

        local v = storage:get(name, key, current_time)
        assert.is_nil(v)
      end)
    end)
  end
end)
