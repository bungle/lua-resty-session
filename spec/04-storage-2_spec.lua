local utils = require "resty.session.utils"

local storage_configs = {
  mysql = {
    username = "root",
    password = "password",
    database = "test",
  },
  postgres = {
    username = "postgres",
    password = "password",
    database = "test",
  },
  redis = {
    prefix = "sessions",
  },
  redis_sentinel = {
    prefix = "sessions",
    password = "password",
    sentinels = {
      { host = "127.0.0.1", port = "26379" }
    },
    connect_timeout = 10000,
    send_timeout    = 10000,
    read_timeout    = 10000,
  },
  redis_cluster = {
    password = "password",
    nodes = {
      { ip = "127.0.0.1", port = "6380" }
    },
    name = "somecluster",
    lock_zone = "sessions",
    connect_timeout = 10000,
    send_timeout    = 10000,
    read_timeout    = 10000,
  },
  memcached = {
    prefix = "sessions",
    connect_timeout = 10000,
    send_timeout    = 10000,
    read_timeout    = 10000,
  },
  dshm = {
    prefix = "sessions",
    connect_timeout = 10000,
    send_timeout = 10000,
    read_timeout = 10000,
  }
}

local function storage_type(ty)
  if ty == "redis_cluster" or ty == "redis_sentinel" then
    return "redis"
  end
  return ty
end

for _, st in ipairs({
  "memcached",
  "mysql",
  "postgres",
  "redis",
  "redis_cluster",
  "redis_sentinel",
  "dshm"
}) do
  describe("Storage tests 2 #noci", function()
    local storage
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
      conf[storage_type(st)] = storage_configs[st]
      storage = utils.load_storage(storage_type(st), conf)
      assert.is_not_nil(storage)
    end)

    describe("[" .. st .. "] storage: SET + GET", function()
      local key     = "test_key"
      local key1    = "test_key_1"
      local key2    = "test_key_2"
      local old_key = "old_test_key"
      local name    = "test_name"
      local value   = "test_value"
      local ttl     = 60

      local audiences = { "foo", "bar" }
      local subjects = { "john", "jane" }

      local metadata = {
        audiences = audiences,
        subjects  = subjects,
      }

      after_each(function()
        storage:delete(name, key, metadata)
        storage:delete(name, key1, metadata)
        storage:delete(name, key2, metadata)
      end)

      it("SET: simple set does not return errors, GET fetches value correctly", function()
        local ok = storage:set(name, key, value, ttl, ngx.time())
        assert.is_not_nil(ok)

        local v, err = storage:get(name, key, ngx.time())
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with metadata and remember works correctly", function()
        local ok = storage:set(name, key, value, ttl, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)
        local v, err = storage:get(name, key, ngx.time())
        assert.is_not_nil(v)
        assert.is_nil(err)
        assert.equals(v, value)
      end)

      it("SET: with metadata (long ttl) correctly appends metadata to collection #pending", function()
        local ok =  storage:set(name, key, value, ttl, ngx.time(), nil, nil, metadata, true)
        ok = ok and storage:set(name, key1, value, ttl, ngx.time(), nil, nil, metadata, true)
        ok = ok and storage:set(name, key2, value, ttl, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)

        for i = 1, #audiences do
          -- TODO: fetch metadata and confirm all the 3 keys above exist
          local meta_values
        end
      end)

      it("SET: with metadata (short ttl) correctly expires metadata #pending", function()
        ttl = 2
        local ok =  storage:set(name, key, value, ttl, ngx.time(), nil, nil, metadata, true)

        ngx.sleep(ttl + 1)

        ok = ok and storage:set(name, key1, value, 60, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)

        for i = 1, #audiences do
          -- TODO: fetch metadata and confirm only key1 above exists (key has expired)
          local meta_values
        end
      end)

      it("SET: with old_key correctly applies stale ttl on old key", function()
        local stale_ttl = 1

        local ok = storage:set(name, old_key, value, ttl, ngx.time())
        assert.is_not_nil(ok)

        ok = storage:set(name, key, value, ttl, ngx.time(), old_key, stale_ttl, nil, false)
        assert.is_not_nil(ok)

        ngx.sleep(3)

        local v = storage:get(name, old_key, ngx.time())
        assert.is_nil(v)
      end)

      it("SET: ttl works as expected", function()
        ttl = 1

        local ok = storage:set(name, key, value, ttl, ngx.time())
        assert.is_not_nil(ok)

        ngx.sleep(3)

        local v = storage:get(name, key, ngx.time())
        assert.is_nil(v)
      end)
    end)

    describe("[" .. st .. "] storage: DELETE", function()
      local name  = "test_name"
      local key   = "test_key"
      local value = "test_value"
      local ttl   = 60

      local audiences = { "foo" }
      local subjects = { "john" }

      local metadata = {
        audiences = audiences,
        subjects  = subjects,
      }

      it("deleted file is not found", function()
        ttl = 1
        local current_time = ngx.time()

        local ok = storage:set(name, key, value, ttl, current_time)
        assert.is_not_nil(ok)

        storage:delete(name, key)

        local v = storage:get(name, key, current_time)
        assert.is_nil(v)
      end)

      it("with metadata correctly deletes metadata collection #pending", function()
        local ok = storage:set(name, key, value, ttl, ngx.time(), nil, nil, metadata, true)
        assert.is_not_nil(ok)

        for i = 1, #audiences do
          -- TODO: fetch metadata and confirm key above exists
          local meta_values

          ok = storage:delete(name, key, metadata)
          assert.is_not_nil(ok)
          -- TODO: fetch metadata again and confirm key above does not exist anymore
        end
      end)
    end)
  end)
end

