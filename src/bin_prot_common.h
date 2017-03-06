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

typedef enum {
    BIN_ERROR_READ,
    BIN_ERROR_RPC,
    BIN_ERROR_INVALID_ARG,
    BIN_ERROR_SUM_TAG,
    BIN_ERROR_NO_VARIANT_MATCH,
} bin_error;

extern zend_class_entry *bin_exn_read;
extern zend_class_entry *bin_exn_rpc;
extern zend_class_entry *bin_exn_invalid_arg;
extern zend_class_entry *bin_exn_sum_tag;
extern zend_class_entry *bin_exn_variant;

void bin_throw(bin_error err, const char *format, ...);

#endif
