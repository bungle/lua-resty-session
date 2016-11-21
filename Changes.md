# Changelog

All notable changes to `lua-resty-session` will be documented in this file.

## [2.13] - 2016-11-21
### Changed
- On start we do send cookie now also if the settings have changed
  and the cookie expiry time needs to be reduced.

### Fixed
- Memcache storage adapter had a missing ngx.null.

## [2.12] - 2016-11-21
### Added
- Implemented pluggable session identifier generators.
- Implemented random session idenfier generator.

### Changed
- Now checks if headers were already sent before trying to set the
  cookie headers.
- SSL session identifier is not checked by default anymore.
- Lua session.identifier.length changed to session.random.length.
- Nginx $session_identifier_length changed to $session_random_length.

## [2.11] - 2016-09-30
### Changed
- Just another OPM release to correct the name.

## [2.10] - 2016-09-29
### Added
- Support for the official OpenResty package manager (opm).

### Changed
- Changed the change log format to keep-a-changelog.

## [2.9] - 2016-09-01
### Fixed
- Bugfix: Weird bug where RAND_bytes was not working on Windows platform.
  Code changed to use resty.random. See Also:
  https://github.com/bungle/lua-resty-session/issues/31
  Thanks @gtuxyco

## [2.8] - 2016-07-05
### Fixed
- Bugfix: AES Cipher used a wrong table for cipher sizes.
  See Also: https://github.com/bungle/lua-resty-session/issues/30
  Thanks @pronan

## [2.7] - 2016-05-18
### Added
- Redis storage adapter now supports Redis authentication.
  See Also: https://github.com/bungle/lua-resty-session/pull/28
  Thanks @cheng5533062

## [2.6] - 2016-04-18
### Changed
- Just cleanups and changed _VERSION to point correct version.

## [2.5] - 2016-04-18
### Fixed
- session.save close argument was not defaulting to true.

## [2.4] - 2016-04-17
### Added
- Cookie will now have SameSite attribute set as "Lax" by default.
  You can turn it off or set to "Strict" by configuration.

### Changed
- Calling save will now also set session.id if the save was called
  without calling start first.
  See Also: https://github.com/bungle/lua-resty-session/issues/27
  Thanks @hcaihao

## [2.3] - 2015-10-16
### Fixed
- Fixes issue #19 where regenerating session would throw an error
  when using cookie storage.
  See Also: https://github.com/bungle/lua-resty-session/issues/19
  Thanks @hulu1522

## [2.2] - 2015-09-17
### Changed
- Removed all session_cipher_* deprecated settings (it was somewhat
  broken in 2.1).
- Changed session secret to be by default 32 bytes random data
  See Also: https://github.com/bungle/lua-resty-session/issues/18
  Thanks @iain-buclaw-sociomantic

### Added
- Added documentation about removed features and corrected about
  session secret size accordingly.

## [2.1] - 2015-09-07
### Added
- Added architecture for Cipher adapter plugins.
  See Also: https://github.com/bungle/lua-resty-session/issues/16
  Thanks @mingfang
- Implemented AES cipher adapter (just like it was before)
- Implemented None cipher adapter (no encryption)
- Added documentation about pluggable ciphers

### Changed
- Changed JSON serializer to use cjson.safe instead

## [2.0] - 2015-08-31
### Added
- Added architecture for Storage adapter plugins.
  See Also: https://github.com/bungle/lua-resty-session/issues/13
- Implemented Client Side Cookie storage adapter.
- Implemented Memcache storage adapter.
  See Also: https://github.com/bungle/lua-resty-session/pull/14
  Thanks @zandbelt
- Implemented Redis storage adapter.
- Implemented Shared Dictionary (shm) storage adapter.
- Added architecture for Encoder and Decoder plugins.
- Implemented Base 64 encoder / decoder.
- Implemented Base 16 (hex) encoder / decoder.
- Added architecture for Serializer plugins
- Implemented JSON serializer.
- Persistent cookies will now also contain Max-Age in addition to Expires.
- Cookie domain attribute is not set anymore if not specified.
- Added notes about using lua-resty-session with Lua code cache turned off.
  See also: https://github.com/bungle/lua-resty-session/issues/15
  Thanks @BizShuk

## [1.7] - 2015-08-03
### Added
- Added session.open() function that only opens a session but doesn't send
  the cookie (until start is called).
  See also: https://github.com/bungle/lua-resty-session/issues/12
  Thanks @junhanamaki
  
### Fixed
- Fixed cookie expiration time format on Firefox bug:
  https://github.com/bungle/lua-resty-session/pull/10
  Thanks @junhanamaki
- Bugfix: Fixed an issue of overwriting a variable:
  https://github.com/bungle/lua-resty-session/pull/11
  Thanks @junhanamaki

## [1.6] - 2015-05-05
### Fixed
- Fixed truncated cookie value bug:
  https://github.com/bungle/lua-resty-session/pull/8
  Thanks @kipras

## [1.5] - 2014-11-27
### Fixed
- Cookies are not always "secure":
  https://github.com/bungle/lua-resty-session/issues/5
  Thanks @vladimir-smirnov-sociomantic

### Added
- Added documentation about Nginx SSL/TLS configuration settings related
  to session lifetime and ssl session ids.


## [1.4] - 2014-11-26
### Fixed
- Bugfix: Fixed an issue where session configurations did get cached
  on a module level. This issue is discussed in pull-request #4:
  https://github.com/bungle/lua-resty-session/pull/4
  Thanks @kipras.

### Added
- Added session.new function.
- Added documentation about Nginx configuration used as defaults (not read
  on every request), and documented session.new.

### Changed
- session.start{ ... } (a call with config parameters) works now as expected.
- session.start now returns additional extra boolean parameter that can be
  used to check if the session is s new session (false) or a previously
  started one (true).

## [1.3] - 2014-11-14
### Added
- Added support for persistent sessions. See issue #2.
- Added session.check.ssi, session.cookie.persistent and the related Nginx
  configuration variables.
- Added Max-Age=0 to expiration code.

## [1.2] - 2014-10-12
### Fixed
- Changed encode and decode functions to operate with correct number of
  arguments. See issue #1.

## [1.1] - 2014-10-03
### Security
- There was a bug where additional user agent, scheme, and remote addr
  (disabled by default) was not checked.

### Added
- Added _VERSION field.

### Changed
- Simplied a code a lot (e.g. internal setcookie and getcookie functions are
  now cleaner). Removed a lot of unneccessary lines from session.start by
  adding configs directly to session prototype.

## [1.0] - 2014-09-24
### Added
- LuaRocks Support via MoonRocks.
