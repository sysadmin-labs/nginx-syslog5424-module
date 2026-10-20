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


/*
 * RFC 5424 section 6.1: a receiver has to accept 480 octets and should
 * accept 2048.  Everything beyond that is cut off here rather than handed
 * to the kernel, which is what nginx does with its own syslog lines.
 */
#define NGX_HTTP_SYSLOG5424_MAX_LINE  2048


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


typedef struct {
    ngx_flag_t    used;                   /* a target exists somewhere */
} ngx_http_syslog5424_main_conf_t;


static ngx_int_t ngx_http_syslog5424_handler(ngx_http_request_t *r);
static void *ngx_http_syslog5424_create_main_conf(ngx_conf_t *cf);
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

    ngx_http_syslog5424_create_main_conf,  /* create main configuration */
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
 * RFC 5424 requires HOSTNAME, APP-NAME and MSGID to be printable ASCII
 * without spaces.  A value breaking that rule would shift every field
 * behind it, so it is replaced by the NIL value.
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


/*
 * Everything that reaches SD and MSG comes from a variable, so it carries
 * whatever the client sent.  A line feed in there ends the record for every
 * receiver that reads datagrams line by line, and the bytes behind it are
 * then a second, forged entry with a priority and a hostname of the
 * client's choosing.  Control characters and the backslash are written as
 * \xHH, the way nginx writes them in an access log.
 */
static size_t
ngx_http_syslog5424_escaped_len(ngx_str_t *s)
{
    size_t  i, n;

    n = 0;

    for (i = 0; i < s->len; i++) {
        if (s->data[i] < 0x20 || s->data[i] == 0x7f || s->data[i] == '\\') {
            n += 3;
        }
    }

    return s->len + n;
}


static u_char *
ngx_http_syslog5424_escape(u_char *dst, u_char *last, ngx_str_t *s)
{
    static u_char   hex[] = "0123456789ABCDEF";

    size_t          i;
    u_char          ch;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch < 0x20 || ch == 0x7f || ch == '\\') {

            if (last - dst < 4) {
                break;
            }

            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[ch >> 4];
            *dst++ = hex[ch & 0x0f];
            continue;
        }

        if (dst == last) {
            break;
        }

        *dst++ = ch;
    }

    return dst;
}


static ngx_int_t
ngx_http_syslog5424_handler(ngx_http_request_t *r)
{
    size_t                         len;
    u_char                        *line, *p, *last;
    ngx_str_t                      msgid, sd, msg, host, tag;
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
                continue;
            }

            if (!ngx_http_syslog5424_printable(&msgid)) {
                msgid = ngx_http_syslog5424_nil;
            }
        }

        if (target[i].sd) {
            if (ngx_http_complex_value(r, target[i].sd, &sd) != NGX_OK) {
                continue;
            }

            if (sd.len == 0) {
                sd = ngx_http_syslog5424_nil;
            }
        }

        if (target[i].message) {
            if (ngx_http_complex_value(r, target[i].message, &msg) != NGX_OK) {
                continue;
            }
        }

        /* "nohostname" is nginx's own parameter and means a NIL HOSTNAME */
        host = target[i].peer->nohostname
                   ? ngx_http_syslog5424_nil : *target[i].peer->hostname;

        if (!ngx_http_syslog5424_printable(&host)) {
            host = ngx_http_syslog5424_nil;
        }

        tag = target[i].peer->tag;

        if (!ngx_http_syslog5424_printable(&tag)) {
            tag = ngx_http_syslog5424_nil;
        }

        /*
         * <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
         *
         * The timestamp is the cached one behind $time_iso8601, so the
         * line costs no call to the clock.
         */
        len = sizeof("<255>1 ") - 1
              + ngx_cached_http_log_iso8601.len + 1
              + host.len + 1
              + tag.len + 1
              + NGX_INT_T_LEN + 1
              + msgid.len + 1
              + ngx_http_syslog5424_escaped_len(&sd) + 1
              + ngx_http_syslog5424_escaped_len(&msg);

        if (len > NGX_HTTP_SYSLOG5424_MAX_LINE) {
            len = NGX_HTTP_SYSLOG5424_MAX_LINE;
        }

        line = ngx_pnalloc(r->pool, len);
        if (line == NULL) {
            return NGX_OK;
        }

        last = line + len;

        pri = target[i].peer->facility * 8 + target[i].peer->severity;

        p = ngx_snprintf(line, len, "<%ui>1 %V %V %V %P %V ",
                         pri,
                         &ngx_cached_http_log_iso8601,
                         &host,
                         &tag,
                         ngx_pid,
                         &msgid);

        /*
         * A structured data element cut in half is not structured data
         * any more, so an SD that does not fit goes out as NIL and the
         * message behind it keeps the room.
         */
        if (ngx_http_syslog5424_escaped_len(&sd) > (size_t) (last - p)) {
            sd = ngx_http_syslog5424_nil;
        }

        p = ngx_http_syslog5424_escape(p, last, &sd);

        if (msg.len && last - p > 1) {
            *p++ = ' ';
            p = ngx_http_syslog5424_escape(p, last, &msg);
        }

        (void) ngx_syslog_send(target[i].peer, line, p - line);
    }

    return NGX_OK;
}


static void *
ngx_http_syslog5424_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_syslog5424_main_conf_t));
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
    ngx_http_syslog5424_main_conf_t    *smcf;
    ngx_http_syslog5424_target_t       *target;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"off\" takes no further parameters");
            return NGX_CONF_ERROR;
        }

        if (scf->targets != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"syslog5424 off\" and a target cannot be "
                               "used in the same block");
            return NGX_CONF_ERROR;
        }

        scf->off = 1;

        return NGX_CONF_OK;
    }

    if (scf->off == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"syslog5424 off\" and a target cannot be used "
                           "in the same block");
        return NGX_CONF_ERROR;
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
     * The destination is parsed by ngx_syslog_process_conf(), so
     * "syslog:server=...", facility, severity and tag mean what they mean
     * in access_log, and the socket is handled by the same code.  The tag
     * is the RFC 5424 APP-NAME.
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

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog5424_module);
    smcf->used = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_syslog5424_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt              *h;
    ngx_http_core_main_conf_t        *cmcf;
    ngx_http_syslog5424_main_conf_t  *smcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog5424_module);

    /* no target anywhere, so no handler in the log phase of every request */
    if (!smcf->used) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_syslog5424_handler;

    return NGX_OK;
}
