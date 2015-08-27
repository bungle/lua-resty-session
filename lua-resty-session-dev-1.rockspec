package = "lua-resty-session"
version = "dev-1"
source = {
    url = "git://github.com/bungle/lua-resty-session.git"
}
description = {
    summary = "Session library for OpenResty implementing Secure Cookie Protocol",
    detailed = "lua-resty-session is a session library for OpenResty implementing Secure Cookie Protocol.",
    homepage = "https://github.com/bungle/lua-resty-session",
    maintainer = "Aapo Talvensaari <aapo.talvensaari@gmail.com>",
    license = "BSD"
}
dependencies = {
    "lua >= 5.1"
}
build = {
    type = "builtin",
    modules = {
        ["resty.session"]                  = "lib/resty/session.lua",
        ["resty.session.utils"]            = "lib/resty/session/utils.lua",
        ["resty.session.storage.shm"]      = "lib/resty/session/storage/shm.lua",
        ["resty.session.storage.redis"]    = "lib/resty/session/storage/redis.lua",
        ["resty.session.storage.cookie"]   = "lib/resty/session/storage/cookie.lua",
        ["resty.session.storage.memcache"] = "lib/resty/session/storage/memcache.lua",
        ["resty.session.serializers.json"] = "lib/resty/session/serializers/json.lua"
    }
}
