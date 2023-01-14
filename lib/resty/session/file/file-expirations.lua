-------------------------------------------------------------------------------
-- Manages a structure of file expiration timestamps
--
-- Structure:
--
--  expirations = {
--    -- sorted list of timestamps
--    ts_arr  = { "1673728377","1673729388","1673738679" },
--    -- buckets of existing file paths by timestamp
--    ts_fn  = {
--      ["1673728377"] = { "file_name_1" = true },
--      ["1673729388"] = { "file_name_2" = true, "file_path_3" = true },
--      ["1673738679"] = { "file_name_4" = true },
--    },
--    -- allows updating a file's expiration (touch)
--    fn_ts = {
--      ["size"]        =          "4",
--      ["file_name_1"] = "1673728377",
--      ["file_name_2"] = "1673729388",
--      ["file_name_3"] = "1673729388",
--      ["file_name_4"] = "1673738679",
--    }
--  }
--

local buffer     = require "string.buffer"
local utils      = require "resty.session.utils"
local file_utils = require "resty.session.file.file-utils"

local run_worker_thread = file_utils.run_worker_thread
local get_path = file_utils.get_path
local inflate = utils.inflate
local deflate = utils.deflate
local encode = buffer.encode
local decode = buffer.decode


local time = ngx.time

local EXP = {}

do
  local EXPIRATIONS_KEY = "exp"
  local LIMIT = math.floor(10^6)
  local time_between_save = 30
  local last_save = 0
  local expirations
  local SIZE = "size"

  local function load_expirations(storage, name)
    local path = get_path(storage, name, EXPIRATIONS_KEY)
    local _, m = run_worker_thread(
      storage.pool,
      "resty.session.file.file-thread",
      "get",
      path
    )
    return m and decode(inflate(m)) or {}
  end

  local function save_expirations(storage, name, ts)
    local path = get_path(storage, name, EXPIRATIONS_KEY)
    local now = time()
    if now - last_save < time_between_save then
      return false
    end

    local ok, res, err = run_worker_thread(
      storage.pool,
      "resty.session.file.file-thread",
      "set",
      path,
      deflate(encode(ts))
    )
    if ok then
      last_save = now
    end
    return ok, res, err
  end

  ---
  -- Finds the position to insert value in sorted array arr.
  --
  -- @function insert_position
  -- @tparam  table   arr the array
  -- @tparam  number  value
  -- @treturn number  insert position
  -- @treturn boolean exists
  local function insert_position(arr, value)
    local i_start, i_end, i_mid = 1, #arr, 1

    while (i_start <= i_end) do
      i_mid = math.floor((i_start + i_end)/2)
      if value < arr[i_mid] then
        i_end = i_mid - 1
      elseif value > arr[i_mid] then
        i_start = i_mid + 1
      else
        return i_mid, true
      end
    end

    local pos
    if arr[i_mid] and value > arr[i_mid] then
      pos = i_mid + 1
    else
      pos = i_mid
    end

    return pos, false
  end

  local function insert_unique(arr, value)
    local pos, found = insert_position(arr, value)

    if found then
      return nil, "value already exists"
    end

    table.insert(arr, pos, value)
    return true
  end

  local function remove(arr, value)
    local pos, found = insert_position(arr, value)

    if not found then
      return nil, "value not found"
    end

    table.remove(arr, pos)
  end

  local function insert_filekey_ts(filekey, ts)
    -- insert in timestamps array
    insert_unique(expirations.tsarr, ts)
    -- set in timestamps/filekeys map
    expirations.ts_fn[ts] = expirations.ts_fn[ts] or {}
    expirations.ts_fn[ts][filekey] = true
    -- update filekeys/timestamps map
    if not expirations.fn_ts[filekey] then
      expirations.fn_ts[SIZE] = (expirations.fn_ts[SIZE] or 0) + 1
    end
    expirations.fn_ts[filekey] = ts
  end

  local function remove_file(file_key)
    local ts = expirations.fn_ts[file_key]
    if ts then
      expirations.fn_ts[SIZE] = expirations.fn_ts[SIZE] - 1
      expirations.fn_ts[file_key] = nil
      if expirations.ts_fn[ts] then
        expirations.ts_fn[ts][file_key] = nil
        if next(expirations.ts_fn[ts]) == nil then
          expirations.ts_fn[ts] = nil
          remove(expirations.tsarr, ts)
        end
      end
      return true
    end
    return false
  end

  local function delete_file(storage, name, file_key)
    local del_path = get_path(storage, name, file_key)
    run_worker_thread(
      storage.pool,
      "resty.session.file.file-thread",
      "delete",
      del_path
    )
  end

  local function drop_oldest(storage, name)
    local last_ts   = expirations.tsarr[#expirations.tsarr]
    local file_keys = expirations.ts_fn[last_ts]

    for k,_ in pairs(file_keys) do
      remove_file(k)
      delete_file(storage, name, k)
    end
  end


  ---
  -- Upserts an expiration time in the expirations table
  --
  -- @function EXP.upsert_ttl
  -- @tparam table  storage the storage
  -- @tparam string name parameter required by the storage
  -- @tparam string file_name name of the file
  -- @tparam number new_ttl the ttl for the file
  -- @tparam number now current unix timestamp
  function EXP.upsert_ttl(storage, name, file_key, new_ttl, now)
    local new_ts
    expirations       = expirations or load_expirations(storage, name)
    expirations.tsarr = expirations.tsarr or {}
    expirations.ts_fn = expirations.ts_fn or {}
    expirations.fn_ts = expirations.fn_ts or {}
    new_ts            = now + new_ttl

    remove_file(file_key)
    insert_filekey_ts(file_key, new_ts)
    if expirations.fn_ts[SIZE] > LIMIT then
      ngx.log(ngx.WARN, "sessions limit reached for file storage:" ..
                       "removing oldest")
      drop_oldest(storage, name)
    end

    local ok, err = save_expirations(storage, name, expirations)
    if not ok then
      return nil, err
    end
  end

  function EXP.delete_expired(storage, name, now, save)
    expirations       = expirations or load_expirations(storage, name)
    expirations.tsarr = expirations.tsarr or {}
    expirations.ts_fn = expirations.ts_fn or {}
    expirations.fn_ts = expirations.fn_ts or {}
    now               = now or time()

    local first_exp = expirations.tsarr and expirations.tsarr[1]
    if not first_exp or first_exp > now then
      return true
    end

    local deleted = {}
    for _, ts in ipairs(expirations.tsarr) do
      if ts > now then
        break
      end

      for del_key, _ in pairs(expirations.ts_fn[ts] or {}) do
        local del_path = get_path(storage, name, del_key)
        local _, res = run_worker_thread(
          storage.pool,
          "resty.session.file.file-thread",
          "delete",
          del_path
        )
        if res then
          deleted[#deleted + 1] = del_key
        end
      end
    end

    for _, d_key in ipairs(deleted) do
      remove_file(d_key)
    end
    if save then
      save_expirations(storage, name, expirations)
    end
    return true
  end

  function EXP.remove_file(storage, name, file_key, save)
    expirations       = expirations or load_expirations(storage, name)
    expirations.tsarr = expirations.tsarr or {}
    expirations.ts_fn = expirations.ts_fn or {}
    expirations.fn_ts = expirations.fn_ts or {}

    remove_file(file_key)

    if save then
      save_expirations(storage, name, expirations)
    end
  end

  function EXP.expires_at(storage, name, file_key)
    expirations = expirations or load_expirations(storage, name)
    return expirations.fn_ts and expirations.fn_ts[file_key]
  end
end

return EXP
