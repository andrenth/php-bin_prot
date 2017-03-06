#include <stdarg.h>

#include <php.h>
#include <Zend/zend_exceptions.h>

#include "bin_prot_common.h"

void *
ptr_of_zval(zval *z)
{
    switch (Z_TYPE_P(z)) {
    case IS_STRING:
        return Z_STRVAL_P(z);
#if PHP_VERSION_ID >= 70000
    case IS_PTR:
        return Z_PTR_P(z);
#else
    case IS_LONG:
        return (void *)(unsigned long)Z_LVAL_P(z);
#endif
    default:
        return NULL;
    }
}

static zend_class_entry *
error_class(bin_error err)
{
    switch (err) {
    case BIN_ERROR_READ:
        return bin_exn_read;
    case BIN_ERROR_RPC:
         return bin_exn_rpc;
    case BIN_ERROR_INVALID_ARG:
         return bin_exn_invalid_arg;
    case BIN_ERROR_SUM_TAG:
         return bin_exn_sum_tag;
    case BIN_ERROR_NO_VARIANT_MATCH:
         return bin_exn_variant;
    }
    return bin_exn_invalid_arg;
}

void
bin_throw(bin_error err, const char *format, ...)
{
    int len;
    va_list args;
    char *message;

    va_start(args, format);
    len = vspprintf(&message, 0, format, args);
    zend_throw_exception(error_class(err), message, 0);
    efree(message);
    va_end(args);
}
