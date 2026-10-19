use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: a target without a message is refused
--- config
    location = /t {
        syslog5424 syslog:server=127.0.0.1:18599;
        return 200 ok;
    }
--- must_die
--- error_log
must have a "message" parameter



=== TEST 2: the first parameter has to name a syslog destination
--- config
    location = /t {
        syslog5424 server=127.0.0.1:18599 message=x;
        return 200 ok;
    }
--- must_die
--- error_log
has to be a syslog destination



=== TEST 3: an unknown parameter is refused
--- config
    location = /t {
        syslog5424 syslog:server=127.0.0.1:18599 message=x nonsense=1;
        return 200 ok;
    }
--- must_die
--- error_log
invalid parameter



=== TEST 4: "off" takes nothing else
--- config
    location = /t {
        syslog5424 off message=x;
        return 200 ok;
    }
--- must_die
--- error_log
takes no further parameters



=== TEST 5: a sound configuration serves as usual
--- config
    location = /t {
        syslog5424 syslog:server=127.0.0.1:18599 'message=$remote_addr $status';
        return 200 ok;
    }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
[alert]



=== TEST 6: several targets on one location are allowed
--- config
    location = /t {
        syslog5424 syslog:server=127.0.0.1:18599 message=one;
        syslog5424 syslog:server=127.0.0.1:18598,facility=local0 message=two;
        return 200 ok;
    }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
[alert]



=== TEST 7: "off" in a location keeps the inherited target quiet
--- http_config
--- config
    syslog5424 syslog:server=127.0.0.1:18599 message=server;
    location = /t {
        syslog5424 off;
        return 200 ok;
    }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
[alert]
