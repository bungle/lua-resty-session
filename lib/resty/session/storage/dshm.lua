local dshm         = require "resty.dshm"

local setmetatable = setmetatable
local tonumber     = tonumber
local concat       = table.concat
local var          = ngx.var

local defaults = {
    region            = var.session_dshm_region                     or "sessions",
    host              = var.session_dshm_host                       or "127.0.0.1",
    port              = tonumber(var.session_dshm_port,         10) or 4321,
    pool              = {
        size          = tonumber(var.session_dshm_pool_size,    10) or 100,
        timeout       = tonumber(var.session_dshm_pool_timeout, 10) or 1000,
    },
}

local storage = {}

storage.__index = storage

function storage.new(session)
    local config = session.dshm or defaults
    local pool   = config.pool  or defaults.pool

    local self = {
        store       = dshm:new(),
        encoder     = session.encoder,
        region      = config.region              or defaults.region,
        host        = config.host                or defaults.host,
        port        = tonumber(config.port,  10) or defaults.port,
        pool        = {
            timeout = tonumber(pool.timeout, 10) or defaults.pool.timeout,
            size    = tonumber(pool.size,    10) or defaults.pool.size,
        },
    }

    return setmetatable(self, storage)
end

function storage:connect()
    return self.store:connect(self.host, self.port)
end

function storage:set_keepalive()
    return self.store:set_keepalive(self.pool_idle_timeout, self.pool_size)
end

function storage:key(id)
    return concat({ self.region, id }, "::")
end

function storage:set(key, ttl, data)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    data, err = self.encoder.encode(data)

    if not data then
        self:set_keepalive()
        return nil, err
    end

    ok, err = self.store:set(key, data, ttl)

    self:set_keepalive()

    return ok, err
end

function storage:get(key)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local data
    data, err = self.store:get(key)
    if data then
        data, err = self.encoder.decode(data)
    end

    self:set_keepalive()

    return data, err
end

function storage:delete(key)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    ok, err = self.store:delete(key)

    self:set_keepalive()

    return ok, err
end

function storage:touch(key, ttl)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    ok, err = self.store:touch(key, ttl)

    self:set_keepalive()

    return ok, err
end

function storage:open(id)
    local key = self:key(id)
    return self:get(key)
end

function storage:save(id, ttl, data)
    local key = self:key(id)
    return self:set(key, ttl, data)
end

function storage:destroy(id)
    local key = self:key(id)
    return self:delete(key)
end

function storage:ttl(id, ttl)
    local key = self:key(id)
    return self:touch(key, ttl)
end

return storage
