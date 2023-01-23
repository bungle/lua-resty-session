---
-- Ensure to keep the tests consistent with those in 04-storage-1_spec.lua

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

for _, st in ipairs({ "file", "shm" }) do
  describe("Storage tests 1", function()
    local storage
    local long_ttl  = 60
    local short_ttl = 2
    local key       = "test_key"
    local key1      = "test_key_1"
    local key2      = "test_key_2"
    local old_key   = "old_test_key"
    local name      = "test_name"
    local value     = "test_value"

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

    describe("[" .. st .. "] storage: SET + GET", function()
      local audiences = { "foo", "bar" }
      local subjects = { "john", "jane" }

      local metadata = {
        audiences = audiences,
        subjects  = subjects,
      }

      after_each(function()
        local now = ngx.time()
        storage:delete(name, key, metadata, now)
        storage:delete(name, key1, metadata, now)
        storage:delete(name, key2, metadata, now)
      end)

      it("SET: simple set does not return errors, GET fetches value correctly", function()
        local now = ngx.time()
        local ok = storage:set(name, key, value, long_ttl, now)
        assert.is_not_nil(ok)

        local v, err = storage:get(name, key, now)
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with metadata and remember works correctly", function()
        local ok = storage:set(name, key, value, long_ttl, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)
        ngx.sleep(1)
        local v, err = storage:get(name, key, ngx.time())
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with metadata (long ttl) correctly appends metadata to collection", function()
        local now = ngx.time()
        local ok = storage:set(name, key, value, long_ttl, now, nil, nil, metadata, true)
        ok = ok and storage:set(name, key1, value, long_ttl, now, nil, nil, metadata, true)
        ok = ok and storage:set(name, key2, value, long_ttl, now, nil, nil, metadata, true)
        assert.is_not_nil(ok)
        ngx.sleep(1)
        for i = 1, #audiences do
          local meta_values = storage:read_metadata(audiences[i], subjects[i], ngx.time())
          assert.is_not_nil(meta_values)
          assert.truthy(meta_values[key ])
          assert.truthy(meta_values[key1])
          assert.truthy(meta_values[key2])
        end
      end)

      it("SET: with metadata (short ttl) correctly expires metadata", function()
        local now = ngx.time()
        local ok = storage:set(name, key, value, short_ttl, now, nil, nil, metadata, true)

        ngx.sleep(short_ttl + 1)

        ok = ok and storage:set(name, key1, value, long_ttl, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)
        ngx.sleep(1)
        for i = 1, #audiences do
          local meta_values = storage:read_metadata(audiences[i], subjects[i], ngx.time())
          assert.falsy(meta_values[key])
          assert.truthy(meta_values[key1])
        end
      end)

      it("SET: with old_key correctly applies stale ttl on old key", function()
        local stale_ttl = 1
        local now = ngx.time()

        local ok = storage:set(name, old_key, value, long_ttl, now)
        assert.is_not_nil(ok)

        ok = storage:set(name, key, value, long_ttl, now, old_key, stale_ttl, nil, false)
        assert.is_not_nil(ok)

        ngx.sleep(3)

        local v = storage:get(name, old_key, ngx.time())
        assert.is_nil(v)
      end)

      it("SET: remember deletes file in old_key", function()
        local stale_ttl = long_ttl
        local now = ngx.time()

        local ok = storage:set(name, old_key, value, long_ttl, now)
        assert.is_not_nil(ok)

        ok = storage:set(name, key, value, long_ttl, now, old_key, stale_ttl, nil, true)
        assert.is_not_nil(ok)

        local v = storage:get(name, old_key, now)
        assert.is_nil(v)
      end)

      it("SET: ttl works as expected", function()
        local now = ngx.time()
        local ok = storage:set(name, key, value, short_ttl, now)
        assert.is_not_nil(ok)

        ngx.sleep(3)

        local v = storage:get(name, key, ngx.time())
        assert.is_nil(v)
      end)
    end)

    describe("[" .. st .. "] storage: DELETE", function()
      local audiences = { "foo" }
      local subjects = { "john" }

      local metadata = {
        audiences = audiences,
        subjects  = subjects,
      }

      it("deleted file is really deleted", function()
        local current_time = ngx.time()

        local ok = storage:set(name, key, value, short_ttl, current_time)
        assert.is_not_nil(ok)

        storage:delete(name, key, nil, current_time)

        local v = storage:get(name, key, current_time)
        assert.is_nil(v)
      end)

      it("with metadata correctly deletes metadata collection", function()
        local now = ngx.time()
        local ok = storage:set(name, key1, value, long_ttl, now, nil, nil, metadata, true)
        assert.is_not_nil(ok)
        ngx.sleep(1)
        for i = 1, #audiences do
          local meta_values = storage:read_metadata(audiences[i], subjects[i], ngx.time())
          assert.truthy(meta_values[key1])
          ok = storage:delete(name, key1, metadata, ngx.time())
          assert.is_not_nil(ok)
          ngx.sleep(2)
          meta_values = storage:read_metadata(audiences[i], subjects[i], ngx.time()) or {}
          assert.falsy(meta_values[key1])
        end
      end)
    end)
  end)
end
