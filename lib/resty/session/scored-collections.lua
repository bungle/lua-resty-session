--------------------------------------------------------------------------
-- Scored Collections
--
-- Allows to manage collections in storages that do not support them
-- out of the box, with the ability to set a different score to each
-- element and remove elements based on a score range.
--
-- Implements a `get_element` `delete_element`, `get` interface to interact
-- with the collection given a key (coll_key).
--

local sha256_encode = require "resty.session.utils".sha256

local function get_element_hash(value)
  return sha256_encode(value)
end


local _SCORED_COLLECTIONS = {}

---
-- Inserts an element in the collection.
--
-- @function scored-collections.insert_element
-- @tparam table storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam string value the value of the element to insert
-- @tparam number score the score for this element
-- @tparam number current_time unix timestamp of current time
function _SCORED_COLLECTIONS.insert_element(
    storage,
    storage_cookie_name,
    coll_key,
    value,
    score
  )
  local collection, err = storage:get(storage_cookie_name, coll_key)
  if err then
    return nil, err
  end
  collection = collection or {}

  collection[get_element_hash(value)] = {
    value = value,
    score = score
  }
  storage:set(storage_cookie_name, coll_key, collection)
end

---
-- Deletes an element from the collection.
--
-- @function scored-collections.delete_element
-- @tparam table  storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam string value the value of the element to delete
function _SCORED_COLLECTIONS.delete_element(
    storage,
    storage_cookie_name,
    coll_key,
    value
  )
  local collection, err = storage:get(storage_cookie_name, coll_key)
  if err then
    return nil, err
  end

  collection[get_element_hash(value)] = nil
  if next(collection) == nil then --empty
    return storage:delete(storage_cookie_name, coll_key)
  end
  return storage:set(storage_cookie_name, coll_key, collection)
end

---
-- Gets all elements from the collection in O(n) with n = #elements.
--
-- @function scored-collections.get
-- @tparam  table storage the storage
-- @tparam  string storage_cookie_name name parameter required by the storage
-- @tparam  string coll_key key to identify the collection
-- @treturn table all the elements
function _SCORED_COLLECTIONS.get(storage, storage_cookie_name, coll_key)
  local elements = {}
  local collection, err = storage:get(storage_cookie_name, coll_key)
  if err then
    return nil, err
  end
  collection = collection or {}

  for _, element in pairs(collection) do
    elements[#elements + 1] = element.value
  end
  return elements
end


---
-- Removes elements from the collection in the provided range.
--
-- @function scored-collections.remove_range_by_score
-- @tparam table storage the storage
-- @tparam string storage_cookie_name name parameter required by the storage
-- @tparam string coll_key key to identify the collection
-- @tparam number range_min lower bound of the range to remove
-- @tparam number range_max upper bound of the range to remove
function _SCORED_COLLECTIONS.remove_range_by_score(
    storage,
    storage_cookie_name,
    coll_key,
    range_min,
    range_max
  )
  -- remove range by score is currently O(n) with n = #elements in the
  -- collection this could be improved with an additional data structure
  -- for scores
  local collection, err = storage:get(storage_cookie_name, coll_key)
  if err then
    return nil, err
  end
  collection = collection or {}

  for _, element in pairs(collection) do
    local min    = range_min
    local max    = range_max
    local score  = element.score
    local delete = min and score >= min and max and score <= max or
                   not min and max and score <= max              or
                   not max and min and score >= min
    if delete then
      collection[get_element_hash(element.value)] = nil
    end
  end

  if next(collection) == nil then --empty
    return storage:delete(storage_cookie_name, coll_key)
  end
  return storage:set(storage_cookie_name, coll_key, collection)
end

return _SCORED_COLLECTIONS
