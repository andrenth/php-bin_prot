#ifndef PHP_BIN_PROT_COMMON_H
#define PHP_BIN_PROT_COMMON_H

#if PHP_VERSION_ID >= 70000
#define SIZE_T size_t
#else
#define add_index_string(z, i, l) add_index_string(z, i, l, 0)
#define SIZE_T int
#endif

extern int le_rpc;
extern int le_conn;

typedef struct _rpc_resource {
    struct bin_rpc *rpc;
} rpc_resource;

typedef struct _conn_resource {
    struct bin_rpc_connection *conn;
} conn_resource;

void *ptr_of_zval(zval *z);

#endif
