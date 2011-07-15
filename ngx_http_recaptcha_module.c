

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t body_index;
} ngx_http_recaptcha_conf_t;


static ngx_int_t ngx_http_recaptcha_form_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static char * ngx_http_add_form_variable(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static void *ngx_http_recaptcha_create_conf(ngx_conf_t *cf);
static char *ngx_http_recaptcha_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_recaptcha_commands[] = {

    { ngx_string("recaptcha_challenge_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_add_form_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("recaptcha_response_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_add_form_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_recaptcha_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_recaptcha_create_conf,          /* create location configuration */
    ngx_http_recaptcha_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_recaptcha_module = {
    NGX_MODULE_V1,
    &ngx_http_recaptcha_module_ctx,          /* module context */
    ngx_http_recaptcha_commands,             /* module directives */
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


static ngx_int_t
ngx_http_recaptcha_form_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *head, *value, *last;
    ngx_str_t                  *name;
    ngx_http_recaptcha_conf_t  *rcf;
    ngx_http_variable_value_t  *vv;

    rcf = ngx_http_get_module_loc_conf(r, ngx_http_recaptcha_module);

    vv = ngx_http_get_indexed_variable(r, rcf->body_index);
    if (vv == NULL || vv->not_found || vv->len == 0) {
        goto not_found;
    }

    name = (ngx_str_t *) data;
    if (name == NULL) {
        goto not_found;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "request_body: \"%*s\", param name = \"%V\"",
                   vv->len, vv->data, name);

    head = ngx_strnstr((u_char *)vv->data, (char *)name->data, (size_t)vv->len);
    if (head == NULL) {
        goto not_found;
    }

    value = head + name->len;

    if (*value != '=') {
        goto not_found;
    }

    value++;

    last = value;

    while (last < (vv->data + vv->len)) {

        if (*last == '&' || *last == CR || *last == LF) {
            break;
        }

        last++;
    }

    v->data = value;
    v->len = last - value;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static char * 
ngx_http_add_form_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                 *value, *str;
    ngx_http_variable_t       *var;

    value = cf->args->elts;

    str = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (str == NULL) {
        return NGX_CONF_ERROR;
    }

    *str = value[1];

    if (str->data[0] == '$') {
        str->data++;
        str->len--;
    }

    var = ngx_http_add_variable(cf, str, 0);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_recaptcha_form_variable;
    var->data = (uintptr_t) str;

    return NGX_CONF_OK;
}


static void *
ngx_http_recaptcha_create_conf(ngx_conf_t *cf)
{
    ngx_http_recaptcha_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_recaptcha_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->body_index = 0;
     */

    conf->body_index = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_recaptcha_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_str_t                  body = ngx_string("request_body");
    ngx_http_recaptcha_conf_t *conf = child;

    conf->body_index = ngx_http_get_variable_index(cf, &body);
    if (conf->body_index == (ngx_uint_t) NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

