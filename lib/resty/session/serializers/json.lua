local json = require "cjson"

return {
    serialize   = json.encode,
    deserialize = json.decode
}