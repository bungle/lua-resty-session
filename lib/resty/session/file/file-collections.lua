--------------------------------------------------------------------------
-- Scored Collections
--
-- Allows to manage scored collections in storages that do not support them out
-- of the box, with the ability to set a different score to each element and
-- remove elements based on a score range.
--
-- Implements a `insert_element` `delete_element`, `get` interface to interact
-- with the collection given a key (coll_key).
--

local utils         = require "resty.session.utils"
local encode        = utils.encode_json
local decode        = utils.decode_json


local _FILE_COLLECTIONS = {}

---
-- Inserts an element in the collection.
--
-- @function file-collections.insert_element
-- @tparam table storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam string value the value of the element to insert
-- @tparam number score the score for this element
-- @tparam number current_time unix timestamp of current time
function _FILE_COLLECTIONS.insert_element(
    storage,
    storage_cookie_name,
    coll_key,
    value,
    score
  )
  local collection = storage:get(storage_cookie_name, coll_key)
  collection = collection and decode(collection) or {}
  collection[value] = score
  storage:set(storage_cookie_name, coll_key, encode(collection))
end

---
-- Deletes an element from the collection.
--
-- @function file-collections.delete_element
-- @tparam table  storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam string value the value of the element to delete
function _FILE_COLLECTIONS.delete_element(
    storage,
    storage_cookie_name,
    coll_key,
    value
  )
  local collection = storage:get(storage_cookie_name, coll_key)
  collection = decode(collection)

  if not collection then
    return nil, string.format("key %s not found", coll_key)
  end

  collection[value] = nil
  if next(collection) == nil then --empty
    return storage:delete(storage_cookie_name, coll_key)
  end
  return storage:set(storage_cookie_name, coll_key, encode(collection))
end

---
-- Gets all elements from the collection in O(n) with n = #elements.
--
-- @function file-collections.get
-- @tparam  table storage the storage
-- @tparam  string storage_cookie_name name parameter required by the storage
-- @tparam  string coll_key key to identify the collection
-- @treturn table all the elements
function _FILE_COLLECTIONS.get(storage, storage_cookie_name, coll_key)
  local elements = {}
  local collection = storage:get(storage_cookie_name, coll_key)
  collection = collection and decode(collection) or {}

  for el_value, _ in pairs(collection) do
    elements[#elements + 1] = el_value
  end
  return elements
end


---
-- Removes elements from the collection in the provided range.
--
-- @function file-collections.remove_range_by_score
-- @tparam table storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam number range_min lower bound of the range to remove
-- @tparam number range_max upper bound of the range to remove
function _FILE_COLLECTIONS.remove_range_by_score(
    storage,
    storage_cookie_name,
    coll_key,
    max_score
  )
  -- remove range by score is currently O(n) with n = #elements in the
  -- collection this could be improved with an additional data structure
  -- for scores
  local collection = storage:get(storage_cookie_name, coll_key)
  collection = collection and decode(collection)
  if not collection then
    return
  end

  for el_value, score in pairs(collection) do
    local delete = max_score and score <= max_score
    if delete then
      collection[el_value] = nil
    end
  end

  if next(collection) == nil then --empty
    return storage:delete(storage_cookie_name, coll_key)
  end
  return storage:set(storage_cookie_name, coll_key, encode(collection))
end

return _FILE_COLLECTIONS
