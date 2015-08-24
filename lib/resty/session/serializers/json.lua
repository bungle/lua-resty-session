local json = require "cjson"

return {
    encode = json.encode,
    decode = json.decode
}