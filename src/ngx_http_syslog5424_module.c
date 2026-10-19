/*
 * Copyright (c) 2026, Jochen Neumeister <joneum@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY DAMAGES WHATSOEVER ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_syslog.h>


typedef struct {
    ngx_syslog_peer_t         *peer;      /* transport, nginx's own */
    ngx_http_complex_value_t  *msgid;     /* MSGID, "-" when absent */
    ngx_http_complex_value_t  *sd;        /* STRUCTURED-DATA, "-" when absent */
    ngx_http_complex_value_t  *message;   /* MSG, may be empty */
} ngx_http_syslog5424_target_t;


typedef struct {
    ngx_array_t  *targets;                /* of ngx_http_syslog5424_target_t */
    ngx_flag_t    off;
} ngx_http_syslog5424_conf_t;


static ngx_int_t ngx_http_syslog5424_handler(ngx_http_request_t *r);
static void *ngx_http_syslog5424_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_syslog5424_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_syslog5424(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_syslog5424_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_syslog5424_commands[] = {

    { ngx_string("syslog5424"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
          |NGX_CONF_1MORE,
      ngx_http_syslog5424,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_syslog5424_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_syslog5424_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_syslog5424_create_loc_conf,   /* create location configuration */
    ngx_http_syslog5424_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_syslog5424_module = {
    NGX_MODULE_V1,
    &ngx_http_syslog5424_module_ctx,       /* module context */
    ngx_http_syslog5424_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_syslog5424_nil = ngx_string("-");


/*
 * RFC 5424 says a HOSTNAME, APP-NAME or MSGID is printable ASCII without
 * spaces.  A value that breaks that rule would split the line into fields
 * the receiver never expected, so it is replaced by the NIL value rather
 * than sent: a log line that lies about its own shape is worse than one
 * that says it does not know.
 */
static ngx_int_t
ngx_http_syslog5424_printable(ngx_str_t *s)
{
    size_t  i;

    if (s->len == 0 || s->len > 255) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        if (s->data[i] < 33 || s->data[i] > 126) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_http_syslog5424_handler(ngx_http_request_t *r)
{
    size_t                         len;
    u_char                        *line, *p;
    ngx_str_t                      msgid, sd, msg;
    ngx_uint_t                     i, pri;
    ngx_http_syslog5424_conf_t    *scf;
    ngx_http_syslog5424_target_t  *target;

    scf = ngx_http_get_module_loc_conf(r, ngx_http_syslog5424_module);

    if (scf->off || scf->targets == NULL) {
        return NGX_OK;
    }

    target = scf->targets->elts;

    for (i = 0; i < scf->targets->nelts; i++) {

        msgid = ngx_http_syslog5424_nil;
        sd = ngx_http_syslog5424_nil;
        ngx_str_null(&msg);

        if (target[i].msgid) {
            if (ngx_http_complex_value(r, target[i].msgid, &msgid) != NGX_OK) {
                return NGX_ERROR;
            }

            if (!ngx_http_syslog5424_printable(&msgid)) {
                msgid = ngx_http_syslog5424_nil;
            }
        }

        if (target[i].sd) {
            if (ngx_http_complex_value(r, target[i].sd, &sd) != NGX_OK) {
                return NGX_ERROR;
            }

            if (sd.len == 0) {
                sd = ngx_http_syslog5424_nil;
            }
        }

        if (target[i].message) {
            if (ngx_http_complex_value(r, target[i].message, &msg) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        /*
         * <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
         *
         * The timestamp is the one nginx already keeps for $time_iso8601,
         * so the line costs no call to the clock.
         */
        len = sizeof("<255>1 ") - 1
              + ngx_cached_http_log_iso8601.len + 1
              + target[i].peer->hostname->len + 1
              + target[i].peer->tag.len + 1
              + NGX_INT_T_LEN + 1
              + msgid.len + 1
              + sd.len + 1
              + msg.len;

        line = ngx_pnalloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        pri = target[i].peer->facility * 8 + target[i].peer->severity;

        p = ngx_sprintf(line, "<%ui>1 %V %V %V %P %V %V",
                        pri,
                        &ngx_cached_http_log_iso8601,
                        target[i].peer->hostname,
                        &target[i].peer->tag,
                        ngx_pid,
                        &msgid,
                        &sd);

        if (msg.len) {
            *p++ = ' ';
            p = ngx_cpymem(p, msg.data, msg.len);
        }

        (void) ngx_syslog_send(target[i].peer, line, p - line);
    }

    return NGX_OK;
}


static void *
ngx_http_syslog5424_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_syslog5424_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_syslog5424_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->off = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_syslog5424_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_syslog5424_conf_t  *prev = parent;
    ngx_http_syslog5424_conf_t  *conf = child;

    ngx_conf_merge_value(conf->off, prev->off, 0);

    if (conf->targets == NULL && !conf->off) {
        conf->targets = prev->targets;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_syslog5424(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_syslog5424_conf_t *scf = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          i;
    ngx_http_syslog5424_target_t       *target;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"off\" takes no further parameters");
            return NGX_CONF_ERROR;
        }

        scf->off = 1;
        scf->targets = NULL;

        return NGX_CONF_OK;
    }

    if (ngx_strncmp(value[1].data, "syslog:", 7) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the first parameter has to be a syslog "
                           "destination, as in "
                           "\"syslog:server=127.0.0.1:514\"");
        return NGX_CONF_ERROR;
    }

    if (scf->targets == NULL) {
        scf->targets = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_http_syslog5424_target_t));
        if (scf->targets == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    target = ngx_array_push(scf->targets);
    if (target == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(target, sizeof(ngx_http_syslog5424_target_t));

    target->peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
    if (target->peer == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * The destination is parsed by nginx itself, so "syslog:server=...",
     * facility, severity and tag mean exactly what they mean in
     * access_log and error_log, and the socket is managed by the same code
     * that manages theirs.  The tag becomes APP-NAME, which is what it is
     * in RFC 5424 terms.
     */
    if (ngx_syslog_process_conf(cf, target->peer) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;

        if (ngx_strncmp(value[i].data, "msgid=", 6) == 0) {
            ccv.value = ngx_palloc(cf->pool, sizeof(ngx_str_t));
            if (ccv.value == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.value->len = value[i].len - 6;
            ccv.value->data = value[i].data + 6;

            target->msgid = ngx_pcalloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (target->msgid == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.complex_value = target->msgid;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "sd=", 3) == 0) {
            ccv.value = ngx_palloc(cf->pool, sizeof(ngx_str_t));
            if (ccv.value == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.value->len = value[i].len - 3;
            ccv.value->data = value[i].data + 3;

            target->sd = ngx_pcalloc(cf->pool,
                                     sizeof(ngx_http_complex_value_t));
            if (target->sd == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.complex_value = target->sd;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "message=", 8) == 0) {
            ccv.value = ngx_palloc(cf->pool, sizeof(ngx_str_t));
            if (ccv.value == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.value->len = value[i].len - 8;
            ccv.value->data = value[i].data + 8;

            target->message = ngx_pcalloc(cf->pool,
                                          sizeof(ngx_http_complex_value_t));
            if (target->message == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.complex_value = target->message;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (target->message == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have a \"message\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_syslog5424_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_syslog5424_handler;

    return NGX_OK;
}
