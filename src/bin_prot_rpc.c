#include <stdlib.h>

#define HAVE_SOCKETS 1

#include <php.h>
#include <ext/sockets/php_sockets.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_interfaces.h>

#include <bin_prot/type_class.h>
#include <bin_prot/rpc.h>

#include "php_bin_prot.h"
#include "bin_prot_common.h"

int le_rpc;
int le_conn;

PHP_FUNCTION(bin_rpc_client)
{
    int         ret;
    int         fd;
    zval       *resource;
    php_socket *php_sock;
    char       *description;
    SIZE_T      len;

    struct bin_rpc_connection *conn;
    conn_resource *conn_res;


    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
            &resource, &description, &len);
    if (ret == FAILURE)
        RETURN_FALSE;

#if PHP_VERSION_ID >= 70000
    php_sock = zend_fetch_resource(Z_RES_P(resource),
                                   php_sockets_le_socket_name,
                                   php_sockets_le_socket());
#else
    ZEND_FETCH_RESOURCE(php_sock, php_socket *, &resource, -1,
                        php_sockets_le_socket_name, php_sockets_le_socket());
#endif

    if (php_sock == NULL)
        RETURN_FALSE;

    conn = bin_rpc_client(php_sock->bsd_socket, description);
    if (conn == NULL)
        RETURN_FALSE;

    conn_res = emalloc(sizeof(conn_resource));
    conn_res->conn = conn;

#if PHP_VERSION_ID >= 70000
    RETURN_RES(zend_register_resource(conn_res, le_conn));
#else
    ZEND_REGISTER_RESOURCE(return_value, conn_res, le_conn);
#endif
}

static int
hash_find_into(HashTable *ht, char *key, zval **res)
{
#if PHP_VERSION_ID >= 70000
    zval *v = zend_hash_str_find(ht, key, strlen(key));
    if (v == NULL)
        return -1;
    *res = v;
#else
    zval **r;
    int ret = zend_hash_find(ht, key, strlen(key) + 1, (void **)&r);
    if (ret == FAILURE)
        return -1;
    *res = *r;
#endif
    return 0;
}

static int
type_class_extract(HashTable *ht, zval **reader, zval **writer, zval **sizer)
{
    int ret;

    ret = hash_find_into(ht, "read", reader);
    if (ret == -1)
        return -1;
    ret = hash_find_into(ht, "write", writer);
    if (ret == -1)
        return -1;
    ret = hash_find_into(ht, "size", sizer);
    if (ret == -1)
        return -1;

    return 0;
}

static int
read_wrapper(void *buf, size_t *pos, void *res, void *data)
{
    int ret;
    zval retval;
    zval *reader = (zval *)data;

#if PHP_VERSION_ID >= 70000
    zval params[2];
    ZVAL_PTR(&params[0], buf);
    ZVAL_LONG(&params[1], *pos);
#else
    zval **params = safe_emalloc(2, sizeof(zval *), 0);
    zval *zbuf = emalloc(sizeof(zval));
    zval *zpos = emalloc(sizeof(zval));
    ZVAL_LONG(zbuf, (long)buf);
    ZVAL_LONG(zpos, *pos);
    params[0] = zbuf;
    params[1] = zpos;
    INIT_ZVAL(retval);
#endif

    ret = call_user_function(CG(function_table), NULL, reader, &retval,
                             2, params TSRMLS_CC);

#if PHP_VERSION_ID < 70000
	efree(zbuf);
	efree(zpos);
    efree(params);
#endif

    if (ret == FAILURE)
        return -1;

    HashTable *ht = Z_ARRVAL(retval);
#if PHP_VERSION_ID >= 70000
    zval *new_res = zend_hash_index_find(ht, 0);
    zval *new_pos = zend_hash_index_find(ht, 1);
    ZVAL_ZVAL(res, new_res, 1, 0);
    *pos = Z_LVAL_P(new_pos);
#else
    zval **new_res;
    zval **new_pos;
    zend_hash_index_find(ht, 0, (void **)&new_res);
    zend_hash_index_find(ht, 1, (void **)&new_pos);
    ZVAL_ZVAL((zval *)res, *new_res, 1, 0);
    *pos = Z_LVAL_P(*new_pos);
#endif
	return ret;
}

static size_t
write_wrapper(void *buf, size_t pos, void *v, void *data)
{
    zval retval;
    zval *writer = (zval *)data;

#if PHP_VERSION_ID >= 70000
    zval params[3];
    ZVAL_PTR(&params[0], buf);
    ZVAL_LONG(&params[1], pos);
    ZVAL_ZVAL(&params[2], v, 0, 0);
#else
    zval **params = safe_emalloc(3, sizeof(zval *), 0);
    zval *zbuf = emalloc(sizeof(zval));
    zval *zpos = emalloc(sizeof(zval));
    zval *zv   = emalloc(sizeof(zval));
    zval *z    = (zval *)v;
    ZVAL_LONG(zbuf, (long)buf);
    ZVAL_LONG(zpos, pos);
    ZVAL_ZVAL(zv, z, 0, 0);
    params[0] = zbuf;
    params[1] = zpos;
    params[2] = zv;
    INIT_ZVAL(retval);
#endif

    call_user_function(CG(function_table), NULL, writer, &retval,
                       3, params TSRMLS_CC);

#if PHP_VERSION_ID < 70000
    efree(zbuf);
    efree(zpos);
    efree(zv);
    efree(params);
#endif

    return Z_LVAL(retval);
}

static size_t
size_wrapper(void *v, void *data)
{
    zval retval;
    zval *sizer = (zval *)data;

#if PHP_VERSION_ID >= 70000
    zval params[1];
    ZVAL_ZVAL(&params[0], v, 0, 0);
    call_user_function(CG(function_table), NULL, sizer, &retval,
                       1, params TSRMLS_CC);
#else
    zval *p;
    zval *zv = (zval *)v;
    MAKE_STD_ZVAL(p);
    ZVAL_ZVAL(p, zv, 0, 0);

    INIT_ZVAL(retval);
    call_user_function(CG(function_table), NULL, sizer, &retval,
                       1, &p TSRMLS_CC);
#endif

    return Z_LVAL(retval);
}

static zval *
call_method(zval *obj, zend_class_entry *ce, const char *method)
{
    zval *res = emalloc(sizeof(*res));
#if PHP_VERSION_ID >= 70000
    zend_call_method(obj, ce, NULL, method, strlen(method), res, 0, NULL, NULL);
#else
    zend_call_method(&obj, ce, NULL, method, strlen(method), &res, 0, NULL, NULL);
#endif
    return res;
}

static zend_class_entry *
fetch_class(const char *name)
{
#if PHP_VERSION_ID >= 70000
    zend_string *zname = zend_string_init(name, strlen(name), 1);
    return zend_fetch_class(zname, ZEND_FETCH_CLASS_DEFAULT TSRMLS_CC);
#else
    return zend_fetch_class(name, strlen(name), ZEND_FETCH_CLASS_DEFAULT TSRMLS_CC);
#endif
}

PHP_FUNCTION(bin_rpc_create)
{
    int        ret;
    char      *tag;
    SIZE_T     tag_len;
    long       version;

    zend_class_entry *bin_query_ce;
    zend_class_entry *bin_response_ce;
    zval *bin_query_obj;
    zval *bin_response_obj;

    zval *query_read,    *query_write,    *query_size;
    zval *response_read, *response_write, *response_size;

    struct bin_type_class_reader *query_reader;
    struct bin_type_class_writer *query_writer;
    struct bin_type_class        *bin_query;

    struct bin_type_class_reader *response_reader;
    struct bin_type_class_writer *response_writer;
    struct bin_type_class        *bin_response;

    struct bin_rpc *rpc;
    rpc_resource *rpc_res;

    const char *type_class = "bin_prot\\type_class\\type_class";
    bin_query_ce    = fetch_class(type_class);
    bin_response_ce = fetch_class(type_class);

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slOO",
            &tag, &tag_len, &version,
            &bin_query_obj, bin_query_ce,
            &bin_response_obj, bin_response_ce);
    if (ret == FAILURE)
        RETURN_FALSE;

    query_read  = call_method(bin_query_obj, bin_query_ce, "read");
    query_write = call_method(bin_query_obj, bin_query_ce, "write");
    query_size  = call_method(bin_query_obj, bin_query_ce, "size");

    query_reader = emalloc(sizeof(*query_reader));
    query_reader->read = read_wrapper;
    query_reader->read_data = query_read;

    query_writer = emalloc(sizeof(*query_writer));
    query_writer->write = write_wrapper;
    query_writer->write_data = query_write;
    query_writer->size = size_wrapper;
    query_writer->size_data = query_size;

    bin_query = emalloc(sizeof(*bin_query));
    bin_query->reader = query_reader;
    bin_query->writer = query_writer;

    response_read  = call_method(bin_response_obj, bin_response_ce, "read");
    response_write = call_method(bin_response_obj, bin_response_ce, "write");
    response_size  = call_method(bin_response_obj, bin_response_ce, "size");

    response_reader = emalloc(sizeof(*response_reader));
    response_reader->read = read_wrapper;
    response_reader->read_data = response_read;

    response_writer = emalloc(sizeof(*response_writer));
    response_writer->write = write_wrapper;
    response_writer->write_data = response_write;
    response_writer->size = size_wrapper;
    response_writer->size_data = response_size;

    bin_response = emalloc(sizeof(*bin_response));
    bin_response->reader = response_reader;
    bin_response->writer = response_writer;

    rpc = emalloc(sizeof(*rpc));
    rpc->tag = strdup(tag);
    rpc->version = version;
    rpc->bin_query = bin_query;
    rpc->bin_response = bin_response;

    rpc_res = emalloc(sizeof(rpc_res));
    rpc_res->rpc = rpc;

#if PHP_VERSION_ID >= 70000
    RETURN_RES(zend_register_resource(rpc_res, le_rpc));
#else
    ZEND_REGISTER_RESOURCE(return_value, rpc_res, le_rpc);
#endif
}

PHP_FUNCTION(bin_rpc_dispatch)
{
    int   ret;
    char *tag;
    zval *z_rpc_res;
    zval *z_conn_res;
    zval *data;
    rpc_resource  *rpc_res;
    conn_resource *conn_res;
#if PHP_VERSION_ID >= 70000
    zval  res;
#else
    zval *res;
#endif

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrz",
            &z_rpc_res, &z_conn_res, &data);
    if (ret == FAILURE)
        RETURN_FALSE;

#if PHP_VERSION_ID >= 70000
    rpc_res = zend_fetch_resource(Z_RES_P(z_rpc_res), PHP_BIN_RPC, le_rpc);
    conn_res = zend_fetch_resource(Z_RES_P(z_conn_res), PHP_BIN_CONN, le_conn);
    ret = bin_rpc_dispatch(rpc_res->rpc, conn_res->conn, data, &res);
#else
    ZEND_FETCH_RESOURCE(rpc_res, rpc_resource *, &z_rpc_res, -1,
                        PHP_BIN_RPC, le_rpc);
    ZEND_FETCH_RESOURCE(conn_res, conn_resource *, &z_conn_res, -1,
                        PHP_BIN_CONN, le_conn);
    MAKE_STD_ZVAL(res);
    ret = bin_rpc_dispatch(rpc_res->rpc, conn_res->conn, data, res);
#endif

    if (ret == -1)
        RETURN_FALSE;

#if PHP_VERSION_ID >= 70000
    RETURN_ZVAL(&res, 0, 0);
#else
    RETURN_ZVAL(res, 0, 0);
#endif
}
