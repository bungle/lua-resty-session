local utils = require "resty.session.utils"
local file_utils = require "resty.session.file.utils"


local fmt = string.format


describe("Testing file utils", function()
  describe("validate file name", function()
    local validate_file_name = file_utils.validate_file_name
    local name = "name"
    local sid1 = "ABCdef123_-iJqwertYUIOpasdfgHJKLzxcvbnmJuis"
    local aud_sub1 = "some-aud:some-sub"
    local simple_prefix = "pref"
    local special_prefix = "@-_-"
    local simple_suffix = "suff"
    local special_suffix = "-_-@"
    local filename_inv1 = "some.conf"
    local filename_inv2 = simple_prefix .. "abc" .. simple_suffix
    local filename_inv3 = simple_prefix .. "_"..name.."_".. "abc" .. simple_suffix


    it("validation fails with invalid files with prefix and suffix", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = simple_prefix,
          suffix = simple_suffix,
        }
      })
      assert.is_false(validate_file_name(storage, name,  filename_inv1))
      assert.is_false(validate_file_name(storage, name,  filename_inv2))
      assert.is_false(validate_file_name(storage, name,  filename_inv3))
    end)


    it("validation fails with invalid files with prefix only", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = simple_prefix
        }
      })
      assert.is_false(validate_file_name(storage, name,  filename_inv1))
      assert.is_false(validate_file_name(storage, name,  filename_inv2))
      assert.is_false(validate_file_name(storage, name,  filename_inv3))
    end)


    it("validation fails with invalid files with suffix only", function()
      local storage = utils.load_storage("file", {
        file = {
          suffix = simple_suffix
        }
      })
      assert.is_false(validate_file_name(storage, name,  filename_inv1))
      assert.is_false(validate_file_name(storage, name,  filename_inv2))
      assert.is_false(validate_file_name(storage, name,  filename_inv3))
    end)


    it("validation fails with invalid files with no prefix or suffix", function()
      local storage = utils.load_storage("file", {})
      assert.is_false(validate_file_name(storage, name,  filename_inv1))
      assert.is_false(validate_file_name(storage, name,  filename_inv2))
      assert.is_false(validate_file_name(storage, name,  filename_inv3))
    end)


    it("validation passes with prefix and suffix", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = simple_prefix,
          suffix = simple_suffix
        }
      })
      local filename_sess = fmt("%s_%s_%s.%s", simple_prefix, name, sid1, simple_suffix)
      local filename_meta = fmt("%s_%s_%s.%s", simple_prefix, name, aud_sub1, simple_suffix)

      assert.is_true(validate_file_name(storage, name,  filename_sess))
      assert.is_true(validate_file_name(storage, name,  filename_meta))
      assert.is_false(validate_file_name(storage, name,  filename_inv1))
      assert.is_false(validate_file_name(storage, name,  filename_inv2))
    end)


    it("validation passes with special prefix and suffix", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = special_prefix,
          suffix = special_suffix
        }
      })
      local sp_filename_sess = fmt("%s_%s_%s.%s", special_prefix, name, sid1, special_suffix)
      local sp_filename_meta = fmt("%s_%s_%s.%s", special_prefix, name, aud_sub1, special_suffix)

      assert.is_true(validate_file_name(storage, name,  sp_filename_sess))
      assert.is_true(validate_file_name(storage, name,  sp_filename_meta))
    end)


    it("validation passes with prefix", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = simple_prefix
        }
      })
      print(require('inspect')(storage))
      local filename_sess = fmt("%s_%s_%s", simple_prefix, name, sid1)
      local filename_meta = fmt("%s_%s_%s", simple_prefix, name, aud_sub1)

      assert.is_true(validate_file_name(storage, name,  filename_sess))
      assert.is_true(validate_file_name(storage, name,  filename_meta))
    end)


    it("validation passes with special prefix", function()
      local storage = utils.load_storage("file", {
        file = {
          prefix = special_prefix
        }
      })
      local sp_filename_sess = fmt("%s_%s_%s", special_prefix, name, sid1)
      local sp_filename_meta = fmt("%s_%s_%s", special_prefix, name, aud_sub1)

      assert.is_true(validate_file_name(storage, name,  sp_filename_sess))
      assert.is_true(validate_file_name(storage, name,  sp_filename_meta))
    end)


    it("validation passes with suffix", function()
      local storage = utils.load_storage("file", {
        file = {
          suffix = simple_suffix
        }
      })
      local filename_sess = fmt("%s_%s.%s", name, sid1, simple_suffix)
      local filename_meta = fmt("%s_%s.%s", name, aud_sub1, simple_suffix)

      assert.is_true(validate_file_name(storage, name,  filename_sess))
      assert.is_true(validate_file_name(storage, name,  filename_meta))
    end)


    it("validation passes with special suffix", function()
      local storage = utils.load_storage("file", {
        file = {
          suffix = special_suffix
        }
      })
      local sp_filename_sess = fmt("%s_%s.%s", name, sid1, special_suffix)
      local sp_filename_meta = fmt("%s_%s.%s", name, aud_sub1, special_suffix)

      assert.is_true(validate_file_name(storage, name,  sp_filename_sess))
      assert.is_true(validate_file_name(storage, name,  sp_filename_meta))
    end)


    it("validation passes with no prefix or suffix", function()
      local storage = utils.load_storage("file", {
        file = {}
      })
      local filename_sess = fmt("%s_%s", name, sid1)
      local filename_meta = fmt("%s_%s", name, aud_sub1)

      assert.is_true(validate_file_name(storage, name,  filename_sess))
      assert.is_true(validate_file_name(storage, name,  filename_meta))
    end)
  end)
end)
