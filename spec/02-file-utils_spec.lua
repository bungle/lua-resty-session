local file_utils = require "resty.session.file.utils"


local describe = describe
local assert = assert
local it = it


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
    local filename_inv2 = "abc"
    local filename_inv3 = name.."_".. "abc"

    it("validation fails with invalid files with prefix and suffix", function()
      assert.is_false(validate_file_name(simple_prefix, simple_suffix, name, filename_inv1))
      assert.is_false(validate_file_name(simple_prefix, simple_suffix, name, filename_inv2))
      assert.is_false(validate_file_name(simple_prefix, simple_suffix, name, filename_inv3))
    end)


    it("validation fails with invalid files with prefix only", function()
      assert.is_false(validate_file_name(simple_prefix, nil, name,  filename_inv1))
      assert.is_false(validate_file_name(simple_prefix, nil, name,  filename_inv2))
      assert.is_false(validate_file_name(simple_prefix, nil, name,  filename_inv3))
    end)

    it("validation fails with invalid files with suffix only", function()
      assert.is_false(validate_file_name(nil, simple_suffix, name, filename_inv1))
      assert.is_false(validate_file_name(nil, simple_suffix, name, filename_inv2))
      assert.is_false(validate_file_name(nil, simple_suffix, name, filename_inv3))
    end)

    it("validation fails with invalid files with no prefix or suffix", function()
      assert.is_false(validate_file_name(nil, nil, name, filename_inv1))
      assert.is_false(validate_file_name(nil, nil, name, filename_inv2))
      assert.is_false(validate_file_name(nil, nil, name, filename_inv3))
    end)

    it("validation passes with prefix and suffix", function()
      assert.is_true(validate_file_name(simple_prefix, simple_suffix, name, sid1))
      assert.is_true(validate_file_name(simple_prefix, simple_suffix, name, aud_sub1))
      assert.is_false(validate_file_name(simple_prefix, simple_suffix, name, filename_inv1))
      assert.is_false(validate_file_name(simple_prefix, simple_suffix, name, filename_inv2))
    end)

    it("validation passes with special prefix and suffix", function()
      assert.is_true(validate_file_name(special_prefix, special_suffix, name, sid1))
      assert.is_true(validate_file_name(special_prefix, special_suffix, name, aud_sub1))
    end)


    it("validation passes with prefix", function()
      assert.is_true(validate_file_name(simple_prefix, nil, name, sid1))
      assert.is_true(validate_file_name(simple_prefix, nil, name, aud_sub1))
    end)

    it("validation passes with special prefix", function()
      assert.is_true(validate_file_name(special_prefix, nil, name, sid1))
      assert.is_true(validate_file_name(special_prefix, nil, name, aud_sub1))
    end)

    it("validation passes with suffix", function()

      assert.is_true(validate_file_name(nil, simple_suffix, name, sid1))
      assert.is_true(validate_file_name(nil, simple_suffix, name, aud_sub1))
    end)

    it("validation passes with special suffix", function()
      assert.is_true(validate_file_name(nil, special_suffix, name, sid1))
      assert.is_true(validate_file_name(nil, special_suffix, name, aud_sub1))
    end)

    it("validation passes with no prefix or suffix", function()
      assert.is_true(validate_file_name(nil, nil, name, sid1))
      assert.is_true(validate_file_name(nil, nil, name, aud_sub1))
    end)
  end)
end)
