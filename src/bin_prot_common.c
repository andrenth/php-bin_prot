#include <php.h>

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
