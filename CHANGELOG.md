# Changelog

## v0.1.0 (2026-10-20)

- First release: `syslog5424` sends an access line in RFC 5424 format,
  with version, RFC 3339 timestamp, hostname, app name, process id,
  message id and structured data.
- The destination is parsed by nginx's own syslog code, so `server=`,
  `facility=`, `severity=` and `tag=` mean what they mean in `access_log`.
- `msgid=`, `sd=` and `message=` take variables.  A `msgid` that is not
  printable ASCII without spaces is replaced by the NIL value.
- Control characters and the backslash from a variable are written as
  `\xHH`, so a client cannot end the record early and append a line of its
  own making.
- A line is cut at 2048 bytes; structured data that does not fit is sent as
  the NIL value instead of being cut in half.
- `nohostname` sends the NIL value in place of the hostname, and a hostname
  or tag that is not printable ASCII does too.
- `syslog5424 off` silences an inherited target, and combining it with a
  target in the same block is a configuration error rather than a directive
  without effect.
- Without a target anywhere in the configuration the module adds no handler
  to the log phase.
