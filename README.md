# nginx-syslog5424-module

[![Build&Test][build-test-badge]][build-test-link]
[![Syslog][syslog-badge]][syslog-link]
[![FreeBSD][freebsd-badge]][freebsd-link]
[![A/UBSan][sanitizers-badge]][sanitizers-link]
[![Valgrind][valgrind-badge]][valgrind-link]
[![Reload][reload-badge]][reload-link]
[![CodeQL][codeql-badge]][codeql-link]
[![Lint][lint-badge]][lint-link]

[build-test-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/build-test.yml/badge.svg
[build-test-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/build-test.yml
[syslog-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/syslog.yml/badge.svg
[syslog-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/syslog.yml
[freebsd-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/freebsd.yml/badge.svg
[freebsd-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/freebsd.yml
[sanitizers-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/sanitizers.yml/badge.svg
[sanitizers-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/sanitizers.yml
[valgrind-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/valgrind.yml/badge.svg
[valgrind-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/valgrind.yml
[reload-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/reload.yml/badge.svg
[reload-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/reload.yml
[codeql-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/codeql.yml/badge.svg
[codeql-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/codeql.yml
[lint-badge]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/lint.yml/badge.svg
[lint-link]: https://github.com/sysadmin-labs/nginx-syslog5424-module/actions/workflows/lint.yml

Access logging to a syslog server in the format of **RFC 5424**, the one
from 2009, instead of the BSD format of RFC 3164 that nginx speaks.

nginx can log to syslog, but only in the old format: a priority, a month,
a day, a clock without a year, a hostname and a tag.  RFC 5424 adds what a
modern collector wants -- a version, an RFC 3339 timestamp with time zone,
an explicit process id, a message id and structured data -- and that is
what this module sends.

## Synopsis

```nginx
http {
    server {
        location / {
            syslog5424 syslog:server=10.0.0.5:514,facility=local1,severity=notice,tag=shop
                       msgid=access
                       'sd=[request@32473 status="$status" bytes="$body_bytes_sent"]'
                       'message=$remote_addr "$request" $http_referer';
        }

        location /health {
            syslog5424 off;
        }
    }
}
```

A line on the wire then reads

```
<141>1 2026-10-19T20:17:38+00:00 shopfront shop 19079 access [request@32473 status="200" bytes="612"] 192.0.2.7 "GET / HTTP/1.1" -
```

## Directives

### `syslog5424`

**syntax:** `syslog5424 syslog:server=<address>[,facility=][,severity=][,tag=] [msgid=<value>] [sd=<value>] message=<value>`
**syntax:** `syslog5424 off`
**context:** `http`, `server`, `location`, `if in location`

The first parameter is the destination, parsed by nginx itself, so
`server=`, `facility=`, `severity=`, `tag=` and `nohostname` mean exactly
what they mean in `access_log` and `error_log`.  The `tag` becomes the
RFC 5424 **APP-NAME**.

`msgid=`, `sd=` and `message=` take variables.  `message=` is required;
`msgid=` and `sd=` default to the NIL value `-`.  A `msgid` that is not
printable ASCII without spaces is replaced by `-` rather than sent, because
a value with a space in it would move every field behind it.

Several targets may be given in one place: each is sent its own datagram.
`syslog5424 off` silences the targets inherited from an enclosing block.

**Quoting.** A parameter whose value carries a space has to be quoted as a
whole, the way nginx quotes: `'message=$remote_addr $status'`, not
`message='$remote_addr $status'`.

## What it does not do yet

* TCP (RFC 6587) and TLS (RFC 5425) transports.  nginx's own syslog code,
  which this module uses for the socket, speaks UDP and unix datagram
  sockets.
* The UTF-8 byte order mark that RFC 5424 allows in front of the message.
* `error_log` in the new format -- the error log is nginx's own and a
  module cannot reach it.

## Building

```sh
./configure --add-module=/path/to/nginx-syslog5424-module
```

or, as a loadable module,

```sh
./configure --add-dynamic-module=/path/to/nginx-syslog5424-module
```

and then `load_module modules/ngx_http_syslog5424_module.so;` in the main
context.

## Testing

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/syslog.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

`ci/syslog.sh` binds a UDP port, drives a few requests through nginx and
holds every field of every datagram against the grammar.

## License

BSD 2-Clause.  See [LICENSE](LICENSE).
