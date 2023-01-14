local fmt = string.format

local run_worker_thread do
  run_worker_thread = ngx.run_worker_thread
  if not run_worker_thread then
    local require = require
    run_worker_thread = function(_, module, func, ...)
      local m = require(module)
      return m[func](...)
    end
  end
end

local function get_path(storage, name, key)
  local path = storage.path
  local prefix = storage.prefix
  local suffix = storage.suffix
  if prefix and suffix then
    return fmt("%s%s_%s_%s.%s", path, prefix, name, key, suffix)
  elseif prefix then
    return fmt("%s%s_%s_%s", path, prefix, name, key)
  elseif suffix then
    return fmt("%s%s_%s.%s", path, name, key, suffix)
  else
    return fmt("%s%s_%s", path, name, key)
  end
end

return {
  run_worker_thread = run_worker_thread,
  get_path = get_path
}
