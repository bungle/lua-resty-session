---
-- File storage backend worker thread module
--
-- @module resty.session.thread


local open = io.open
local remove = os.remove


---
-- Store data in file.
--
-- @function set
-- @tparam  string   path     file path
-- @tparam  string   content  file content
-- @treturn true|nil ok
-- @treturn string   error message
local function set(path, content)
  local file, err = open(path, "wb")
  if not file then
    return nil, err
  end

  local ok, err = file:write(content)

  file:close()

  if not ok then
    remove(path)
    return nil, err
  end

  return true
end


---
-- Append data in file.
--
-- @function append
-- @tparam  string   path     file path
-- @tparam  string   data  file data
-- @treturn true|nil ok
-- @treturn string   error message
local function append(path, data)
  local file, err = open(path, "a")
  if not file then
    return nil, err
  end

  local ok, err = file:write(data)

  file:close()

  if not ok then
    remove(path)
    return nil, err
  end

  return true
end


---
-- Read data from a file.
--
-- @function get
-- @tparam  string  path file to read
-- @treturn string|nil content
-- @treturn string     error message
local function get(path)
  local file, err = open(path, "rb")
  if not file then
    return nil, err
  end

  local content, err = file:read("*a")

  file:close()

  if not content then
    return nil, err
  end

  return content
end


---
-- Delete a file.
--
-- @function delete
-- @tparam  string  path file to read
-- @treturn string|nil ok
-- @treturn string     error message
local function delete(path)
  return remove(path)
end


return {
  set = set,
  get = get,
  delete = delete,
  append = append,
}
