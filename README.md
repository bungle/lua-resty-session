# lua-resty-session

**lua-resty-session** is a secure, and flexible session library for OpenResty.


## Configuration

The configuration can be divided to generic session configuration and the server
side storage configuration.

Here is an example:

```lua
init_by_lua_block {
  require "resty.session".init({
    remember = true,
    store_metadata = true,
    secret = "RaJKp8UQW1",
    secret_fallbacks = {
      "X88FuG1AkY",
      "fxWNymIpbb",
    },
    storage = "postgres",
    postgres = {
      username = "my-service",
      password = "kVgIXCE5Hg",
      database = "sessions",
    },
  })
}
```


### Session Configuration

Session configuration can be passed to [initialization](#initialization), [constructor](#constructors),
and [helper](#helpers) functions.

Here are the possible session configuration options:

| Option                      |   Default    | Description                                                                                                                                                                                                                                                                                          |
|-----------------------------|:------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `secret`                    |    `nil`     | Secret used for the key derivation. The secret is hashed with SHA-256 before using it. E.g. `"RaJKp8UQW1"`.                                                                                                                                                                                          |
| `secret_fallbacks`          |    `nil`     | Array of secrets that can be used as alternative secrets (when doing key rotation), E.g. `{ "6RfrAYYzYq", "MkbTkkyF9C" }`.                                                                                                                                                                           |
| `ikm`                       |   (random)   | Initial key material (or ikm) can be specified directly (without using a secret) with exactly 32 bytes of data. E.g. `"5ixIW4QVMk0dPtoIhn41Eh1I9enP2060"`                                                                                                                                            |
| `ikm_fallbacks`             |    `nil`     | Array of initial key materials that can be used as alternative keys (when doing key rotation), E.g. `{ "QvPtlPKxOKdP5MCu1oI3lOEXIVuDckp7" }`.                                                                                                                                                        |
| `cookie_prefix`             |              | Cookie prefix, use `nil`, `"__Host-"` or `"__Secure-"`.                                                                                                                                                                                                                                              |
| `cookie_name`               | `"session"`  | Session cookie name, e.g. `"session"`.                                                                                                                                                                                                                                                               |
| `cookie_path`               |    `"/"`     | Cookie path, e.g. `"/"`.                                                                                                                                                                                                                                                                             |
| `cookie_http_only`          |    `true`    | Mark cookie HTTP only, use `true` or `false`.                                                                                                                                                                                                                                                        |
| `cookie_secure`             |    `nil`     | Mark cookie secure, use `nil`, `true` or `false`.                                                                                                                                                                                                                                                    |
| `cookie_priority`           |    `nil`     | Cookie priority, use `nil`, `"Low"`, `"Medium"`, or `"High"`.                                                                                                                                                                                                                                        |
| `cookie_same_site`          |   `"Lax"`    | Cookie same-site policy, use `nil`, `"Lax"`, `"Strict"`, `"None"`, or `"Default"`                                                                                                                                                                                                                    |
| `cookie_same_party`         |    `nil`     | Mark cookie with same party flag, use `nil`, `true`, or `false`.                                                                                                                                                                                                                                     |
| `cookie_partitioned`        |    `nil`     | Mark cookie with partitioned flag, use `nil`, `true`, or `false`.                                                                                                                                                                                                                                    |
| `remember`                  |   `false`    | Enable or disable persistent sessions, use `nil`, `true`, or `false`.                                                                                                                                                                                                                                |
| `remember_safety`           |  `"Medium"`  | Remember cookie key derivation complexity, use `nil`, `"None"` (fast), `"Low"`, `"Medium"`, `"High"` or `"Very High"` (slow).                                                                                                                                                                        |
| `remember_cookie_name`      | `"remember"` | Persistent session cookie name, e.g. `"remember"`.                                                                                                                                                                                                                                                   |
| `audience`                  | `"default"`  | Session audience, e.g. `"my-application"`.                                                                                                                                                                                                                                                           |
| `subject`                   |    `nil`     | Session subject, e.g. `"john.doe@example.com"`.                                                                                                                                                                                                                                                      |
| `enforce_same_subject`      |   `false`    | When set to `true`, audiences need to share the same subject. The library removes non-subject matching audience data on save.                                                                                                                                                                        |
| `stale_ttl`                 |     `10`     | When session is saved a new session is created, stale ttl specifies how long the old one can still be used, e.g. `10` (in seconds).                                                                                                                                                                  |
| `idling_timeout`            |    `900`     | Idling timeout specifies how long the session can be inactive until it is considered invalid, e.g. `900` (15 minutes) (in seconds), `0` disables the checks and touching.                                                                                                                            |
| `rolling_timeout`           |    `3600`    | Rolling timeout specifies how long the session can be used until it needs to be renewed, e.g. `3600` (an hour) (in seconds), `0` disables the checks and rolling.                                                                                                                                    |
| `absolute_timeout`          |   `86400`    | Absolute timeout limits how long the session can be renewed, until re-authentication is required, e.g. `86400` (a day) (in seconds), `0` disables the checks.                                                                                                                                        |
| `remember_rolling_timeout`  |   `604800`   | Remember timeout specifies how long the persistent session is considered valid, e.g. `604800` (a week) (in seconds), `0` disables the checks and rolling.                                                                                                                                            |
| `remember_absolute_timeout` |  `2592000`   | Remember absolute timeout limits how long the persistent session can be renewed, until re-authentication is required, e.g. `2592000` (30 days) (in seconds), `0` disables the checks.                                                                                                                |
| `hash_storage_key`          |    `true`    | Whether to hash or not the storage key. With storage key hashed it is impossible to decrypt data on server side without having a cookie too, use `nil`, `true` or `false`.                                                                                                                           |
| `hash_subject`              |   `false`    | Whether to hash or not the subject when `store_metadata` is enabled, e.g. for PII reasons.                                                                                                                                                                                                           |
| `store_metadata`            |   `false`    | Whether to also store metadata of sessions, such as collecting data of sessions for a specific audience belonging to a specific subject.                                                                                                                                                             |
| `touch_threshold`           |     `60`     | Touch threshold controls how frequently or infrequently the `session:refresh` touches the cookie, e.g. `60` (a minute) (in seconds)                                                                                                                                                                  |
| `compression_threshold`     |    `1024`    | Compression threshold controls when the data is deflated, e.g. `1024` (a kilobyte) (in bytes), `0` disables compression.                                                                                                                                                                             |
| `request_headers`           |    `nil`     | Set of headers to send to upstream, use `id`, `audience`, `subject`, `timeout`, `idling-timeout`, `rolling-timeout`, `absolute-timeout`. E.g. `{ "id", "timeout" }` will set `Session-Id` and `Session-Timeout` request headers when `set_headers` is called.                                        |
| `response_headers`          |    `nil`     | Set of headers to send to downstream, use `id`, `audience`, `subject`, `timeout`, `idling-timeout`, `rolling-timeout`, `absolute-timeout`. E.g. `{ "id", "timeout" }` will set `Session-Id` and `Session-Timeout` response headers when `set_headers` is called.                                     |
| `storage`                   |    `nil`     | Storage is responsible of storing session data, use `nil` or `"cookie"` (data is stored in cookie), `"dshm"`, `"file"`, `"memcached"`, `"mysql"`, `"postgres"`, `"redis"`, or `"shm"`, or give a name of custom module (`"custom-storage"`), or a `table` that implements session storage interface. |
| `dshm`                      |    `nil`     | Configuration for dshm storage, e.g. `{ prefix = "sessions" }` (see below)                                                                                                                                                                                                                           |
| `file`                      |    `nil`     | Configuration for file storage, e.g. `{ path = "/tmp", suffix = "session" }` (see below)                                                                                                                                                                                                             |
| `memcached`                 |    `nil`     | Configuration for memcached storage, e.g. `{ prefix = "sessions" }` (see below)                                                                                                                                                                                                                      |
| `mysql`                     |    `nil`     | Configuration for MySQL / MariaDB storage, e.g. `{ database = "sessions" }` (see below)                                                                                                                                                                                                              |
| `postgres`                  |    `nil`     | Configuration for Postgres storage, e.g. `{ database = "sessions" }` (see below)                                                                                                                                                                                                                     |
| `redis`                     |    `nil`     | Configuration for Redis / Redis Sentinel / Redis Cluster storages, e.g. `{ prefix = "sessions" }` (see below)                                                                                                                                                                                        |
| `shm`                       |    `nil`     | Configuration for shared memory storage, e.g. `{ zone = "sessions" }`                                                                                                                                                                                                                                |
| `["custom-storage"]`        |    `nil`     | custom storage (loaded with `require "custom-storage"`) configuration.                                                                                                                                                                                                                               |


### Cookie Storage Configuration

When storing data to cookie, there is no additional configuration required,
just set the `storage` to `nil` or `"cookie"`.


### DSHM Storage Configuration

With DHSM storage you can use the following settings (set the `storage` to `"dshm"`):

| Option              |    Default    | Description                                                                                  |
|---------------------|:-------------:|----------------------------------------------------------------------------------------------|
| `prefix`            |     `nil`     | The Prefix for the keys stored in DSHM.                                                      |
| `suffix`            |     `nil`     | The suffix for the keys stored in DSHM.                                                      |
| `host`              | `"127.0.0.1"` | The host to connect.                                                                         |
| `port`              |    `4321`     | The port to connect.                                                                         |
| `connect_timeout`   |     `nil`     | Controls the default timeout value used in TCP/unix-domain socket object's `connect` method. |
| `send_timeout`      |     `nil`     | Controls the default timeout value used in TCP/unix-domain socket object's `send` method.    |
| `read_timeout`      |     `nil`     | Controls the default timeout value used in TCP/unix-domain socket object's `receive` method. |
| `keepalive_timeout` |     `nil`     | Controls the default maximal idle time of the connections in the connection pool.            |
| `pool`              |     `nil`     | A custom name for the connection pool being used.                                            |
| `pool_size`         |     `nil`     | The size of the connection pool.                                                             |
| `backlog`           |     `nil`     | A queue size to use when the connection pool is full (configured with pool_size).            |
| `ssl`               |     `nil`     | Enable SSL.                                                                                  |
| `ssl_verify`        |     `nil`     | Verify server certificate.                                                                   |
| `server_name`       |     `nil`     | The server name for the new TLS extension Server Name Indication (SNI).                      |


### File Storage Configuration

With file storage you can use the following settings (set the `storage` to `"file"`):

| Option              |     Default     | Description                                                                         |
|---------------------|:---------------:|-------------------------------------------------------------------------------------|
| `prefix`            |      `nil`      | File prefix for session file.                                                       |
| `suffix`            |      `nil`      | File suffix (or extension without `.`) for session file.                            |
| `pool`              |      `nil`      | Name of the thread pool under which file writing happens (available on Linux only). |
| `path`              | (tmp directory) | Path (or directory) under which session files are created.                          |


### Memcached Storage Configuration

With file Memcached you can use the following settings (set the `storage` to `"memcached"`):

| Option              |   Default   | Description                                                                                  |
|---------------------|:-----------:|----------------------------------------------------------------------------------------------|
| `prefix`            |    `nil`    | Prefix for the keys stored in memcached.                                                     |
| `suffix`            |    `nil`    | Suffix for the keys stored in memcached.                                                     |
| `host`              | `127.0.0.1` | The host to connect.                                                                         |
| `port`              |   `11211`   | The port to connect.                                                                         |
| `socket`            |    `nil`    | The socket file to connect to.                                                               |
| `connect_timeout`   |    `nil`    | Controls the default timeout value used in TCP/unix-domain socket object's `connect` method. |
| `send_timeout`      |    `nil`    | Controls the default timeout value used in TCP/unix-domain socket object's `send` method.    |
| `read_timeout`      |    `nil`    | Controls the default timeout value used in TCP/unix-domain socket object's `receive` method. |
| `keepalive_timeout` |    `nil`    | Controls the default maximal idle time of the connections in the connection pool.            |
| `pool`              |    `nil`    | A custom name for the connection pool being used.                                            |
| `pool_size`         |    `nil`    | The size of the connection pool.                                                             |
| `backlog`           |    `nil`    | A queue size to use when the connection pool is full (configured with pool_size).            |
| `ssl`               |   `false`   | Enable SSL                                                                                   |
| `ssl_verify`        |    `nil`    | Verify server certificate                                                                    |
| `server_name`       |    `nil`    | The server name for the new TLS extension Server Name Indication (SNI).                      |


### MySQL / MariaDB Storage Configuration

With file MySQL / MariaDB you can use the following settings (set the `storage` to `"mysql"`):

| Option              |      Default      | Description                                                                                  |
|---------------------|:-----------------:|----------------------------------------------------------------------------------------------|
| `host`              |   `"127.0.0.1"`   | The host to connect.                                                                         |
| `port`              |      `3306`       | The port to connect.                                                                         |
| `socket`            |       `nil`       | The socket file to connect to.                                                               |
| `username`          |       `nil`       | The database username to authenticate.                                                       |
| `password`          |       `nil`       | Password for authentication, may be required depending on server configuration.              |
| `charset`           |     `"ascii"`     | The character set used on the MySQL connection.                                              |
| `database`          |       `nil`       | The database name to connect.                                                                |
| `table_name`        |   `"sessions"`    | Name of database table to which to store session data.                                       |
| `table_name_meta`   | `"sessions_meta"` | Name of database meta data table to which to store session meta data.                        |
| `max_packet_size`   |     `1048576`     | The upper limit for the reply packets sent from the MySQL server (in bytes).                 |
| `connect_timeout`   |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `connect` method. |
| `send_timeout`      |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `send` method.    |
| `read_timeout`      |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `receive` method. |
| `keepalive_timeout` |       `nil`       | Controls the default maximal idle time of the connections in the connection pool.            |
| `pool`              |       `nil`       | A custom name for the connection pool being used.                                            |
| `pool_size`         |       `nil`       | The size of the connection pool.                                                             |
| `backlog`           |       `nil`       | A queue size to use when the connection pool is full (configured with pool_size).            |
| `ssl`               |      `false`      | Enable SSL.                                                                                  |
| `ssl_verify`        |       `nil`       | Verify server certificate.                                                                   |

You also need to create following tables in your database:

```mysql
--
-- Database table that stores session data.
--
CREATE TABLE IF NOT EXISTS sessions (
  sid  CHAR(43) PRIMARY KEY,
  name TINYTEXT,
  data MEDIUMTEXT,
  exp  DATETIME,
  INDEX (exp)
) CHARACTER SET ascii;

--
-- Sessions metadata table.
--
-- This is only needed if you want to store session metadata.
--
CREATE TABLE IF NOT EXISTS sessions_meta (
  aud TINYTEXT,
  sub TINYTEXT,
  sid CHAR(43),
  PRIMARY KEY (aud, sub, sid),
  CONSTRAINT FOREIGN KEY (sid) REFERENCES sessions(sid) ON DELETE CASCADE ON UPDATE CASCADE
) CHARACTER SET ascii;
```


### Postgres Configuration

With file Postgres you can use the following settings (set the `storage` to `"postgres"`):

| Option              |      Default      | Description                                                                                               |
|---------------------|:-----------------:|-----------------------------------------------------------------------------------------------------------|
| `host`              |   `"127.0.0.1"`   | The host to connect.                                                                                      |
| `port`              |      `5432`       | The port to connect.                                                                                      |
| `application`       |      `5432`       | Set the name of the connection as displayed in pg_stat_activity (defaults to `"pgmoon"`).                 |
| `username`          |   `"postgres"`    | The database username to authenticate.                                                                    |
| `password`          |       `nil`       | Password for authentication, may be required depending on server configuration.                           |
| `database`          |       `nil`       | The database name to connect.                                                                             |
| `table_name`        |   `"sessions"`    | Name of database table to which to store session data (can be `database schema` prefixed).                |
| `table_name_meta`   | `"sessions_meta"` | Name of database meta data table to which to store session meta data (can be `database schema` prefixed). |
| `connect_timeout`   |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `connect` method.              |
| `send_timeout`      |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `send` method.                 |
| `read_timeout`      |       `nil`       | Controls the default timeout value used in TCP/unix-domain socket object's `receive` method.              |
| `keepalive_timeout` |       `nil`       | Controls the default maximal idle time of the connections in the connection pool.                         |
| `pool`              |       `nil`       | A custom name for the connection pool being used.                                                         |
| `pool_size`         |       `nil`       | The size of the connection pool.                                                                          |
| `backlog`           |       `nil`       | A queue size to use when the connection pool is full (configured with pool_size).                         |
| `ssl`               |      `false`      | Enable SSL.                                                                                               |
| `ssl_verify`        |       `nil`       | Verify server certificate.                                                                                |
| `ssl_required`      |       `nil`       | Abort the connection if the server does not support SSL connections.                                      |

You also need to create following tables in your database:

```postgres
--
-- Database table that stores session data.
--
CREATE TABLE IF NOT EXISTS sessions (
  sid  TEXT PRIMARY KEY,
  name TEXT,
  data TEXT,
  exp  TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ON sessions (exp);

--
-- Sessions metadata table.
--
-- This is only needed if you want to store session metadata.
--
CREATE TABLE IF NOT EXISTS sessions_meta (
  aud TEXT,
  sub TEXT,
  sid TEXT REFERENCES sessions (sid) ON DELETE CASCADE ON UPDATE CASCADE,
  PRIMARY KEY (aud, sub, sid)
);
```


### Redis Configuration

The session library supports single Redis, Redis Sentinel, and Redis Cluster
connections. Common configuration settings among them all:

| Option              | Default | Description                                                                                  |
|---------------------|:-------:|----------------------------------------------------------------------------------------------|
| `prefix`            |  `nil`  | Prefix for the keys stored in Redis.                                                         |
| `suffix`            |  `nil`  | Suffix for the keys stored in Redis.                                                         |
| `username`          |  `nil`  | The database username to authenticate.                                                       |
| `password`          |  `nil`  | Password for authentication.                                                                 |
| `connect_timeout`   |  `nil`  | Controls the default timeout value used in TCP/unix-domain socket object's `connect` method. |
| `send_timeout`      |  `nil`  | Controls the default timeout value used in TCP/unix-domain socket object's `send` method.    |
| `read_timeout`      |  `nil`  | Controls the default timeout value used in TCP/unix-domain socket object's `receive` method. |
| `keepalive_timeout` |  `nil`  | Controls the default maximal idle time of the connections in the connection pool.            |
| `pool`              |  `nil`  | A custom name for the connection pool being used.                                            |
| `pool_size`         |  `nil`  | The size of the connection pool.                                                             |
| `backlog`           |  `nil`  | A queue size to use when the connection pool is full (configured with pool_size).            |
| `ssl`               | `false` | Enable SSL                                                                                   |
| `ssl_verify`        |  `nil`  | Verify server certificate                                                                    |
| `server_name`       |  `nil`  | The server name for the new TLS extension Server Name Indication (SNI).                      |

The `single redis` implementation is selected when you don't pass either `sentinels` or `nodes`,
which would lead to selecting `sentinel` or `cluster` implementation.

#### Single Redis Configuration

Single Redis has following additional configuration options (set the `storage` to `"redis"`):

| Option      |     Default     | Description                    |
|-------------|:---------------:|--------------------------------|
| `host`      |  `"127.0.0.1"`  | The host to connect.           |
| `port`      |     `6379`      | The port to connect.           |
| `socket`    |      `nil`      | The socket file to connect to. |
| `database`  |      `nil`      | The database to connect.       |


#### Redis Sentinels Configuration

Redis Sentinel has following additional configuration options (set the `storage` to `"redis"`
and configure the `sentinels`):

| Option              | Default  | Description                    |
|---------------------|:--------:|--------------------------------|
| `master`            |  `nil`   | Name of master.                |
| `role`              |  `nil`   | `"master"` or `"slave"`.       |
| `socket`            |  `nil`   | The socket file to connect to. |
| `sentinels`         |  `nil`   | Redis Sentinels.               |
| `sentinel_username` |  `nil`   | Optional sentinel username.    |
| `sentinel_password` |  `nil`   | Optional sentinel password.    |
| `database`          |  `nil`   | The database to connect.       |

The `sentinels` is an array of Sentinel records:

| Option | Default | Description          |
|--------|:-------:|----------------------|
| `host` |  `nil`  | The host to connect. |
| `port` |  `nil`  | The port to connect. |

The `sentinel` implementation is selected when you pass `sentinels` as part of `redis`
configuration (and do not pass `nodes`, which would select `cluster` implementation).


#### Redis Cluster Configuration

Redis Cluster has following additional configuration options (set the `storage` to `"redis"`
and configure the `nodes`):

| Option                    | Default | Description                    |
|---------------------------|:-------:|--------------------------------|
| `name`                    |  `nil`  | Redis cluster name.            |
| `nodes`                   |  `nil`  | Redis cluster nodes.           |
| `socket`                  |  `nil`  | The socket file to connect to. |
| `lock_zone`               |  `nil`  | Redis Sentinels.               |
| `lock_prefix`             |  `nil`  | Optional sentinel username.    |
| `max_redirections`        |  `nil`  | Optional sentinel password.    |
| `max_connection_attempts` |  `nil`  | The database to connect.       |
| `max_connection_timeout`  |  `nil`  | The database to connect.       |

The `nodes` is an array of Cluster node records:

| Option |    Default    | Description                |
|--------|:-------------:|----------------------------|
| `ip`   | `"127.0.0.1"` | The IP address to connect. |
| `port` |    `6379`     | The port to connect.       |

The `cluster` implementation is selected when you pass `nodes` as part of `redis`
configuration.

For `cluster` to work properly, you need to configure `lock_zone`, so also add this
to your Nginx configuration:

```nginx
lua_shared_dict redis_cluster_locks 100k;
```

And set the `lock_zone` to `"redis_cluster_locks"`


### SHM Configuration

With SHM storage you can use the following settings (set the `storage` to `"shm"`):

| Option   |   Default    | Description                        |
|----------|:------------:|------------------------------------|
| `prefix` |    `nil`     | Prefix for the keys stored in SHM. |
| `suffix` |    `nil`     | Suffix for the keys stored in SHM. |
| `zone`   | `"sessions"` | A name of shared memory zone.      |

You will also need to create a shared dictionary `zone` in Nginx:

```nginx
lua_shared_dict sessions 10m;
```

Note: you may need to adjust the size of shared memory zone according
to your needs.


## API

### Initialization

- session.init

### Constructors

- session.new

### Helpers

- session.open
- session.start
- session.logout
- session.destroy

### Instance Methods

- session:open
- session:restore
- session:persist
- session:set
- session:get
- session:set_subject
- session:get_subject
- session:set_audience
- session:get_audience
- session.info:set
- session.info:get
- session.info:save
- session:save
- session:touch
- session:refresh
- session:logout
- session:destroy
- session:close
- session:hide


## Cookie Format

```
[ HEADER ----------------------------------------------------------------------------------------------------]
[ Type || Flags || Session ID || Creation Time || Rolling Offset || Data Size || Tag || Idling Offset || Mac ]
[ 1B   || 2B    || 32B        || 5B            || 4B             || 3B        || 16B || 3B            || 16B ]
```

and

```
[ PAYLOAD --]
[ Data  *B  ]   
```

Both the `HEADER` and `PAYLOAD` are base64 url-encoded before putting in a `Set-Cookie` header.
When using a server side storage, the `PAYLOAD` is not put in the cookie. With cookie storage
the base64 url-encoded header is concatenated with base64 url-encoded payload.

The `HEADER` is fixed size 82 bytes binary or 110 bytes in base64 url-encoded form.

Header fields explained:

- Type: number `1` binary packed in a single little endian byte (currently the only supported `type`).
- Flags: binary packed flags (short) in a two byte little endian form.
- Session ID: `32` bytes of crypto random data.
- Creation Time: binary packed secs from epoch in a little endian form, truncated to 5 bytes.
- Rolling Offset: binary packed secs from creation time in a little endian form (integer). 
- Data Size: binary packed data size (short) in a two byte little endian form.
- Tag: `16` bytes of authentication tag from AES-256-GCM encryption of the data.
- Idling Offset: binary packed secs from creation time + rolling offset in a little endian form, truncated to 3 bytes.
- Mac: `16` bytes message authentication code of the header.


## Data Encryption

1. Initial keying material (IKM):
   1. derive IKM from `secret` by hashing `secret` with SHA-256, or
   2. use 32 byte IKM when passed to library with `ikm`
2. Generate 32 bytes of crypto random session id (`sid`) 
3. Derive 32 byte encryption key and 12 byte initialization vector with HKDF using SHA-256 
   1. Use HKDF extract to derive a new key from `ikm` to get `key` (this step can be done just once per `ikm`):
      - output length: `32`
      - digest: `"sha256"`
      - key: `<ikm>`
      - mode: `extract only`
      - info: `""`
      - salt: `""`
   2. Use HKDF expand to derive `44` bytes of `output`:
      - output length: `44`
      - digest: `"sha256"`
      - key: `<key>`
      - mode: `expand only`
      - info: `"encryption:<sid>"`
      - salt: `""`
   3. The first 32 bytes are the encryption key (`aes-key`), and the last 12 bytes are the initialization vector (`iv`)
4. Encrypt `plaintext` (JSON encoded and optionally deflated) using AES-256-GCM to get `ciphertext` and `tag`
   1. cipher: `"aes-256-gcm"`
   2. key: `<aes-key>`
   3. iv: `<iv>`
   4. plaintext: `<plaintext>`
   5. aad: use the first 47 bytes of `header` as `aad`, that includes:
      1. Type
      2. Flags
      3. Session ID
      4. Creation Time
      5. Rolling Offset
      6. Data Size

There is a variation for `remember` cookies on step 3, where we may use `PBKDF2` instead of `HKDF`, depending
on `remember_safety` setting. The `PBKDF2` settings:

- outlen: `44`
- md: `"sha256"`
- pass: `<key>`
- salt: `"encryption:<sid>"`
- pbkdf2_iter: `<1000|10000|100000|1000000>`

Iteration counts are based on `remember_safety` setting (`"Low"`, `"Medium"`, `"High"`, `"Very High"`),
if `remember_safety` is set to `"None"`, we will use the HDKF as above.


## Message Authentication Code Calculation

1. Derive 32 byte authentication key (`mac_key`) with HKDF using SHA-256:
    1. Use HKDF extract to derive a new key from `ikm` to get `key` (this step can be done just once per `ikm` and reused with encryption key generation):
        - output length: `32`
        - digest: `"sha256"`
        - key: `<ikm>`
        - mode: `extract only`
        - info: `""`
        - salt: `""`
    2. Use HKDF expand to derive `32` bytes of `output`:
        - output length: `32`
        - digest: `"sha256"`
        - key: `<key>`
        - mode: `expand only`
        - info: `"authentication:<sid>"`
        - salt: `""`
    3. The first 32 bytes are the encryption key (`aes-key`), and the last 12 bytes are the initialization vector (`iv`)
2. Calculate message authentication code using HMAC-SHA256:
   -  digest: `"sha256"`
   -  message: use the first 47 bytes of `header` as `aad`, that includes:
      1. Type
      2. Flags
      3. Session ID
      4. Creation Time
      5. Rolling Offset
      6. Data Size
      7. Tag
      8. Idling Offset


## License

`lua-resty-session` uses two clause BSD license.

```
Copyright (c) 2014 – 2023 Aapo Talvensaari, 2022 – 2023 Samuele Illuminati
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
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
```
