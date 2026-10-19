#!/bin/sh
#
# Catch what the module sends and check it against RFC 5424.
#
# A test suite can see the response but not the datagram, and the datagram
# is the whole product of this module.  So a small receiver sits on a UDP
# port, nginx is pointed at it, and every field of every line that arrives
# is held against the grammar:
#
#     <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
#
# usage: ci/syslog.sh <nginx binary>
#
# Set SYSLOG_LOAD_MODULE to the path of ngx_http_syslog5424_module.so to
# test a loadable build.

set -eu

NGINX=${1:?path to the nginx binary missing}
WORK=${CI_WORK:-$(cd "$(dirname "$0")/.." && pwd)/ci-work}/syslog
PORT=${SYSLOG_HTTP_PORT:-18540}
UDP=${SYSLOG_UDP_PORT:-18541}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }
command -v perl > /dev/null || { echo "perl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs"

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

load=
[ -n "${SYSLOG_LOAD_MODULE:-}" ] && load="load_module $SYSLOG_LOAD_MODULE;"

cat > "$WORK/conf/nginx.conf" <<CONF
$load
daemon on;
master_process on;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log info;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;

    server {
        listen 127.0.0.1:$PORT;

        location /plain {
            syslog5424 syslog:server=127.0.0.1:$UDP 'message=plain \$status';
            return 200 "x";
        }

        location /full {
            syslog5424 syslog:server=127.0.0.1:$UDP,facility=local1,severity=notice,tag=myapp
                       msgid=access
                       'sd=[probe@32473 status="\$status" uri="\$uri"]'
                       'message=full \$request_uri';
            return 200 "x";
        }

        location /badid {
            syslog5424 syslog:server=127.0.0.1:$UDP 'msgid=two words'
                       message=badid;
            return 200 "x";
        }

        location /quiet {
            syslog5424 off;
            return 200 "x";
        }
    }
}
CONF

cat > "$WORK/receiver.pl" <<'PERL'
use strict;
use warnings;
use IO::Socket::INET;

# Everything that arrives within the window is written out line by line.
# The window ends on its own so the script can never hang a workflow.

my ($port, $seconds) = @ARGV;

my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port,
                              Proto => 'udp') or die "bind: $!\n";

$| = 1;
my $end = time + $seconds;

while (time < $end) {
    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "tick\n" };
        alarm 1;
        $s->recv($buf, 8192);
        alarm 0;
    };
    print "$buf\n" if length $buf;
}
PERL

cleanup() {
	# every line survives a failure of its own: this runs from an EXIT
	# trap under set -e, where a failed test aborts the function and
	# makes its status the status of the whole script
	if [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	if [ -n "${rpid:-}" ]; then
		kill "$rpid" 2>/dev/null || true
	fi
	sleep 1
}
trap cleanup EXIT INT TERM

perl "$WORK/receiver.pl" "$UDP" 8 > "$WORK/caught.txt" &
rpid=$!
sleep 1

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
sleep 1

curl -s -o /dev/null "http://127.0.0.1:$PORT/plain"
curl -s -o /dev/null "http://127.0.0.1:$PORT/full?a=b"
curl -s -o /dev/null "http://127.0.0.1:$PORT/badid"
curl -s -o /dev/null "http://127.0.0.1:$PORT/quiet"

sleep 3
kill "$rpid" 2>/dev/null
wait "$rpid" 2>/dev/null || true

echo "--- what arrived ---"
sed 's/^/  /' "$WORK/caught.txt"

lines=$(grep -c . "$WORK/caught.txt" || true)
[ "$lines" -eq 3 ] ||
	note "expected three datagrams, got $lines (the \"off\" location must send nothing)"

echo "--- the plain line ---"
plain=$(grep ' plain ' "$WORK/caught.txt" || true)
case $plain in
"<190>1 "*) echo "  priority 190, local7.info as nginx defaults it" ;;
*) note "wrong or missing priority: $plain" ;;
esac
echo "$plain" | grep -qE '^<190>1 [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2} [^ ]+ nginx [0-9]+ - - plain 200$' ||
	note "the plain line does not match the grammar: $plain"

echo "--- the line with everything set ---"
full=$(grep ' full ' "$WORK/caught.txt" || true)
echo "$full" | grep -qE '^<141>1 [^ ]+ [^ ]+ myapp [0-9]+ access \[probe@32473 status="200" uri="/full"\] full /full\?a=b$' ||
	note "the full line does not match the grammar: $full"

echo "--- a msgid that is not printable ASCII becomes the NIL value ---"
bad=$(grep ' badid' "$WORK/caught.txt" || true)
echo "$bad" | grep -qE ' - - badid$' ||
	note "a msgid with a space was passed through: $bad"

echo "--- the error log ---"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/error.log"; then
	note "alert or emerg in the error log"
	grep -E '\[(alert|emerg)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/syslog.sh: failed" >&2; exit 1; }
echo "ci/syslog.sh: ok"
