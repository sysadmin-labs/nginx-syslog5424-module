# Changelog

Newest first.  Dates are release dates.

## v0.1.0 (2026-10-19)

### Added

- First release.  `syslog5424` sends an access line to a syslog server in
  the format of RFC 5424: version, RFC 3339 timestamp with time zone,
  hostname, app name, process id, message id and structured data.

- The destination is parsed by nginx's own syslog code, so `server=`,
  `facility=`, `severity=` and `tag=` mean what they mean in `access_log`,
  and the socket is managed by the same code that manages nginx's.

- `msgid=`, `sd=` and `message=` take variables.  A `msgid` that is not
  printable ASCII without spaces is replaced by the NIL value instead of
  being sent, because a space in that field moves every field behind it.

- `syslog5424 off` silences an inherited target.

### Why this module exists

nginx speaks the BSD syslog format of RFC 3164 and nothing else.  Asking
for the 2009 format is an open ticket on trac (#2284) and an open issue on
GitHub, and no third-party module fills the gap.
