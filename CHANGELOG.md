# Changelog

## v0.1.0 (2026-10-19)

- First release: `syslog5424` sends an access line in RFC 5424 format,
  with version, RFC 3339 timestamp, hostname, app name, process id,
  message id and structured data.
- The destination is parsed by nginx's own syslog code, so `server=`,
  `facility=`, `severity=` and `tag=` mean what they mean in `access_log`.
- `msgid=`, `sd=` and `message=` take variables.  A `msgid` that is not
  printable ASCII without spaces is replaced by the NIL value.
- `syslog5424 off` silences an inherited target.
