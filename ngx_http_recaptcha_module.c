

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t  challenge;
    ngx_str_t  response;
    ngx_uint_t body_index;
} ngx_http_recaptcha_conf_t;


static ngx_int_t ngx_http_recaptcha_challenge_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_recaptcha_response_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_recaptcha_create_conf(ngx_conf_t *cf);
static char *ngx_http_recaptcha_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_recaptcha_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_recaptcha_commands[] = {

    { ngx_string("recaptcha_challenge_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_recaptcha_conf_t, challenge),
      NULL },

    { ngx_string("recaptcha_response_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_recaptcha_conf_t, response),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_recaptcha_module_ctx = {
    ngx_http_recaptcha_add_variables,        /* preconfiguration */
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


static ngx_str_t  ngx_http_recaptcha_challenge_name = 
ngx_string("recaptcha_challenge");

static ngx_str_t  ngx_http_recaptcha_response_name =
ngx_string("recaptcha_set_expires");


static ngx_int_t
ngx_http_recaptcha_challenge_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->data = NULL;
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_recaptcha_response_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = NULL;

    return NGX_OK;
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
     *     conf->challenge = {0, NULL};
     *     conf->response = {0, NULL};
     *     conf->body_index = 0;
     */

    conf->body_index = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_recaptcha_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_str_t                  body = ngx_string("request_body");
    ngx_http_recaptcha_conf_t *prev = parent;
    ngx_http_recaptcha_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->challenge, prev->challenge, 
            "recaptcha_challenge_field");

    ngx_conf_merge_str_value(conf->response, prev->response, 
            "recaptcha_response_field");

    conf->body_index = ngx_http_get_variable_index(cf, &body);
    if (conf->body_index == (ngx_uint_t) NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_recaptcha_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_recaptcha_challenge_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_recaptcha_challenge_variable;

    var = ngx_http_add_variable(cf, &ngx_http_recaptcha_response_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_recaptcha_response_variable;

    return NGX_OK;
}
