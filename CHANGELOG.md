# Changelog

## v0.1.0 (2026-10-20)

- First release: `syslog5424` sends an access line in RFC 5424 format,
  with version, RFC 3339 timestamp, hostname, app name, process id,
  message id and structured data.
- The destination is parsed by nginx's own syslog code, so `server=`,
  `facility=`, `severity=` and `tag=` mean what they mean in `access_log`.
- `msgid=`, `sd=` and `message=` take variables.  A `msgid` that is not
  printable ASCII without spaces is replaced by the NIL value.
- The value of a variable is escaped, the text around it is not: in `sd=`
  the element is taken as written and every variable inside it is escaped as
  RFC 5424 section 6.3.3 asks, so a client cannot leave the element it was
  put in.  Control characters are written as `\xHH`, so a client cannot end
  the record early and append a line of its own making.
- A line is cut at 2048 bytes; structured data that does not fit is sent as
  the NIL value instead of being cut in half.
- `nohostname` sends the NIL value in place of the hostname, and so does a
  hostname, tag or message id that is not printable ASCII or longer than
  RFC 5424 allows for that field.
- `syslog5424 off` silences an inherited target, combining it with a target
  in the same block is a configuration error rather than a directive without
  effect, and a block with a target of its own is not silenced by an `off`
  further out.
- Without a target anywhere in the configuration the module adds no handler
  to the log phase.
