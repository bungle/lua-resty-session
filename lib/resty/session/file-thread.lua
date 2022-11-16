local open = io.open
local remove = os.remove


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


local function delete(path)
  return remove(path)
end


return {
  set = set,
  get = get,
  delete = delete,
}
