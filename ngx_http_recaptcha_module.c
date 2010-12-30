

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_http_complex_value_t  *variable;
    ngx_http_complex_value_t  *md5;
    
    time_t                     expires;
} ngx_http_secure_cookie_conf_t;


static ngx_int_t ngx_http_secure_cookie_set_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_cookie_set_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_secure_cookie_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_cookie_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_secure_cookie_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_secure_cookie_commands[] = {

    { ngx_string("secure_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, variable),
      NULL },

    { ngx_string("secure_cookie_md5"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, md5),
      NULL },

    { ngx_string("secure_cookie_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, expires),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_cookie_module_ctx = {
    ngx_http_secure_cookie_add_variables,    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_secure_cookie_create_conf,      /* create location configuration */
    ngx_http_secure_cookie_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_secure_cookie_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_cookie_module_ctx,      /* module context */
    ngx_http_secure_cookie_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_secure_cookie_name = ngx_string("secure_cookie");

static ngx_str_t  ngx_http_secure_cookie_set_md5_name = 
ngx_string("secure_cookie_set_md5");

static ngx_str_t  ngx_http_secure_cookie_set_expires_name = 
ngx_string("secure_cookie_set_expires");


static ngx_int_t
ngx_http_secure_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                          hash_buf[16], md5_buf[16];
    u_char                         *p, *last;
    ngx_str_t                       val, hash;
    time_t                          expires;
    ngx_md5_t                       md5;
    ngx_http_secure_cookie_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->variable, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie: \"%V\"", &val);

    last = val.data + val.len;

    p = ngx_strlchr(val.data, last, ',');
    expires = 0;

    if (p) {
        val.len = p++ - val.data;

        expires = ngx_atotm(p, last - p);
        if (expires <= 0) {
            goto not_found;
        }
    }

    if (val.len > 24) {
        goto not_found;
    }

    hash.len = 16;
    hash.data = hash_buf;

    if (ngx_decode_base64(&hash, &val) != NGX_OK) {
        goto not_found;
    }

    if (hash.len != 16) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->md5, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie md5: \"%V\"", &val);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(md5_buf, &md5);

    if (ngx_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    v->data = (u_char *) ((expires && expires < ngx_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_set_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                           md5_buf[16];
    ngx_str_t                        res, val;
    ngx_md5_t                        md5;
    ngx_http_secure_cookie_conf_t   *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, sclcf->md5, &val) != NGX_OK) {
        goto not_found;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie set md5 base string: \"%V\"", &val);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(md5_buf, &md5);

    res.len = 24;
    res.data = ngx_pcalloc(r->pool, res.len);
    if (res.data == NULL) {
        goto not_found;
    }

    val.len = 16;
    val.data = md5_buf;
    ngx_encode_base64(&res, &val);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie set md5 base64: \"%V\"", &res);

    v->len = res.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = res.data;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_set_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                         *last, *time;
    time_t                          expires;
    ngx_http_secure_cookie_conf_t  *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    time = ngx_palloc(r->pool, 64);
    if (time == NULL) {
        goto not_found;
    }

    expires = ngx_time() + sclcf->expires;

    last = ngx_snprintf(time, 64, "%T", expires);

    v->len = last - time;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = time;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_secure_cookie_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_cookie_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_cookie_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->variable = NULL;
     *     conf->md5 = NULL;
     *     conf->expires = 0;
     */

    conf->expires = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_secure_cookie_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_cookie_conf_t *prev = parent;
    ngx_http_secure_cookie_conf_t *conf = child;

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    if (conf->md5 == NULL) {
        conf->md5 = prev->md5;
    }

    ngx_conf_merge_sec_value(conf->expires, prev->expires, 24 * 60 * 60);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_cookie_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_secure_cookie_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secure_cookie_variable;

    var = ngx_http_add_variable(cf, &ngx_http_secure_cookie_set_md5_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secure_cookie_set_md5_variable;

    var = ngx_http_add_variable(cf, &ngx_http_secure_cookie_set_expires_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secure_cookie_set_expires_variable;

    return NGX_OK;
}
