# lua-resty-session

**lua-resty-session** is a session library for OpenResty implementing [Secure Cookie Protocol](http://www.cse.msu.edu/~alexliu/publications/Cookie/cookie.pdf).

## Hello World with lua-resty-session

```nginx
http {
    server {
        listen       8080;
        server_name  localhost;
        default_type text/html;
        location / {
            content_by_lua '
                ngx.say("<html><body><a href=/start>Start the test</a>!</body></html>")
            ';
        }
        location /start {
            content_by_lua '
                local session = require "resty.session".start()
                session.data.name = "OpenResty Fan"
                session:save()
                ngx.say("<html><body>Session started. ",
                        "<a href=/test>Check if it is working</a>!</body></html>")
            ';
        }
        location /test {
            content_by_lua '
                local session = require "resty.session".start()
                ngx.say("<html><body>Session was started by <strong>",
                        session.data.name or "Anonymous",
                        "</strong>! <a href=/destroy>Destroy the session</a>.</body></html>")
            ';
        }
        location /destroy {
            content_by_lua '
                local session = require "resty.session".start()
                session:destroy()
                ngx.say("<html><body>Session was destroyed. ",
                        "<a href=/check>Is it really so</a>?</body></html>")
            ';
        }
        location /check {
            content_by_lua '
                local session = require "resty.session".start()
                ngx.say("<html><body>Session was really destroyed, you are known as <strong>",
                        session.data.name or "Anonymous",
                        "</strong>! <a href=/>Start again</a>.</body></html>")
            ';
        }
    }
}
```

## Lua API

#### table session.start(opts or nil)

With this function you can start a new session. It will create a new session Lua ```table``` on each call.
Right now you should only start session once as calling this function repeatedly will overwrite the previously
started session cookie. This function will return a new session ```table``` as a result. If the session cookie
is supplied with user's HTTP(S) client then this function validates the supplied session cookie. If validation
is successful, the user supplied session data will be used (if not, a new session is generated with empty data).
You may supply optional session configuration variables with ```opts``` argument, but be aware that many of these
will only have effect if the session is a fresh session (i.e. not loaded from user supplied cookie). This function
does also manage session cookie renewing configured with ```$session_cookie_renew```. E.g. it will send a new cookie
with a new expiration time if the following is met ```self.expires - now < session.cookie.renew```.

```lua
local session = require "resty.template".start()
-- Set some options (overwriting the defaults or nginx configuration variables)
local session = require "resty.template".start{ identifier = { length = 32 }}
```

#### boolean session:regenerate(flush or nil)

This function regenerates a session. It will generate a new session identifier and optionally flush the
session data if ```flush``` argument evaluates ```true```. It will automatically ```session:save``` which
means that a new expires flag is set on the cookie, and the data is encrypted with the new parameters. With
client side sessions (server side sessions are not yet supported) this overwrites the current cookie with
a new one (but it doesn't invalidate the old one as there is no state held on server side - invalidation
actually happens when the cookie's expiration time is not valid anymore). This function returns a boolean
value if everything went as planned (you may assume that it is always the case).

```lua
local session = require "resty.template".start()
session:regenerate()
-- Flush the current data
session:regenerate(true)
```

#### boolean session:save()

This function saves the session and sends a new cookie to client (with a new expiration time and ecnrypted data).
You need to call this function whenever you want to save the changes made to ```session.data``` table. It is
adviced that you call this function only once per request (no need to encrypt and set cookie many times).
This function returns a boolean value if everything went as planned (you may assume that it is always the case).

#### boolean session:destroy()

This function will immediately set session data to empty table ```{}```. It will also send a new cookie to
client with empty data and Expires flag ```Expires=Thu, 01 Jan 1970 00:00:01 GMT``` (meaning that the client
should remove the cookie, and not send it back again). This function returns a boolean value if everything went
as planned (you may assume that it is always the case).

```lua
local session = require "resty.template".start()
session:destroy()
```

####

## License

`lua-resty-session` uses two clause BSD license.

```
Copyright (c) 2014, Aapo Talvensaari
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES`