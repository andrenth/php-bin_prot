#include <stdlib.h>

#include <php.h>
#include <Zend/zend_exceptions.h>

#include <bin_prot/size.h>

#include "php_bin_prot.h"
#include "bin_prot_common.h"

#define DEFINE_SIZER(name, php_param)                                      \
PHP_FUNCTION(bin_size_##name)                                              \
{                                                                          \
    int     ret;                                                           \
    long    v;                                                             \
                                                                           \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, php_param, &v); \
    if (ret == FAILURE)                                                    \
        RETURN_FALSE;                                                      \
                                                                           \
    RETURN_LONG(bin_size_##name((void *)&v));                              \
}

DEFINE_SIZER(nat0,          "l")
DEFINE_SIZER(int,           "l")
DEFINE_SIZER(int32,         "l")
DEFINE_SIZER(int64,         "l")
DEFINE_SIZER(int_8bit,      "l")
DEFINE_SIZER(int_16bit,     "l")
DEFINE_SIZER(int_32bit,     "l")
DEFINE_SIZER(int_64bit,     "l")
DEFINE_SIZER(network16_int, "l")
DEFINE_SIZER(network32_int, "l")
DEFINE_SIZER(network64_int, "l")
DEFINE_SIZER(variant_int,   "l")
DEFINE_SIZER(float,         "d")

#define DEFINE_STRING_SIZER(name)                                    \
PHP_FUNCTION(bin_size_##name)                                        \
{                                                                    \
    int     ret;                                                     \
    zval   *z;                                                       \
                                                                     \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z); \
    if (ret == FAILURE)                                              \
        RETURN_FALSE;                                                \
                                                                     \
    RETURN_LONG(bin_size_##name(ptr_of_zval(z)));                    \
}

DEFINE_STRING_SIZER(string);
DEFINE_STRING_SIZER(digest);

PHP_FUNCTION(bin_size_unit)
{
    RETURN_LONG(bin_size_unit(NULL));
}

PHP_FUNCTION(bin_size_char)
{
    int     ret;
    zval   *z;
    char   *v;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z);
    if (ret == FAILURE)
        RETURN_FALSE;

    v = (char *)ptr_of_zval(z);
    RETURN_LONG(bin_size_char(&v[0]));
}

struct sizer_callback_args {
    zend_fcall_info       *fci;
    zend_fcall_info_cache *fci_cache;
    zval                  *val;
};

static size_t
sizer_callback(void *arg)
{
    struct sizer_callback_args *args = (struct sizer_callback_args *)arg;

#if PHP_VERSION_ID >= 70000
    zval params[1];
    ZVAL_ZVAL(&params[0], args->val, 1, 1);
#else
    zval ***params = safe_emalloc(1, sizeof(zval **), 0);
    zval *p = emalloc(sizeof(zval));
    ZVAL_ZVAL(p, args->val, 0, 0);
    params[0] = &p;
#endif
    args->fci->params = params;
    args->fci->param_count = 1;

    zend_call_function(args->fci, args->fci_cache);

#if PHP_VERSION_ID >= 70000
    return Z_LVAL_P(args->fci->retval);
#else
    efree(p);
    efree(params);
    return Z_LVAL_P(*args->fci->retval_ptr_ptr);
#endif
}

PHP_FUNCTION(bin_size_option)
{
    int     ret;
    zval   *v;
#if PHP_VERSION_ID >= 70000
    zval    res;
#else
    zval   *res;
#endif

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    struct sizer_callback_args args;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fz",
            &fci, &fci_cache, &v);
    if (ret == FAILURE)
        RETURN_FALSE;

    if (Z_TYPE_P(v) == IS_NULL)
        RETURN_LONG(bin_size_option(sizer_callback, NULL));

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.val = v;

    RETURN_LONG(bin_size_option(sizer_callback, &args));
}

PHP_FUNCTION(bin_size_pair)
{
    size_t  ret;
    zval   *v1;
    zval   *v2;
#if PHP_VERSION_ID >= 70000
    zval    res1;
    zval    res2;
#else
    zval   *res1;
    zval   *res2;
#endif

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    struct sizer_callback_args args1;
    struct sizer_callback_args args2;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffzz",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &v1, &v2);

#if PHP_VERSION_ID >= 70000
    fci1.retval = &res1;
    fci2.retval = &res2;
#else
    fci1.retval_ptr_ptr = &res1;
    fci2.retval_ptr_ptr = &res2;
#endif
    args1.fci = &fci1;
    args1.fci_cache = &fci_cache1;
    args1.val = v1;

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.val = v2;

    RETURN_LONG(bin_size_pair(sizer_callback, sizer_callback, &args1, &args2));
}

PHP_FUNCTION(bin_size_triple)
{
    size_t  ret;
    zval   *v1;
    zval   *v2;
    zval   *v3;
#if PHP_VERSION_ID >= 70000
    zval    res1;
    zval    res2;
    zval    res3;
#else
    zval   *res1;
    zval   *res2;
    zval   *res3;
#endif

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    zend_fcall_info fci3;
    zend_fcall_info_cache fci_cache3;

    struct sizer_callback_args args1;
    struct sizer_callback_args args2;
    struct sizer_callback_args args3;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fffzzz",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &fci3, &fci_cache3,
            &v1, &v2, &v3);

#if PHP_VERSION_ID >= 70000
    fci1.retval = &res1;
    fci2.retval = &res2;
    fci3.retval = &res3;
#else
    fci1.retval_ptr_ptr = &res1;
    fci2.retval_ptr_ptr = &res2;
    fci3.retval_ptr_ptr = &res3;
#endif
    args1.fci = &fci1;
    args1.fci_cache = &fci_cache1;
    args1.val = v1;

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.val = v2;

    args3.fci = &fci3;
    args3.fci_cache = &fci_cache3;
    args3.val = v3;

    RETURN_LONG(bin_size_triple(sizer_callback, sizer_callback, sizer_callback,
                                &args1, &args2, &args3));
}

PHP_FUNCTION(bin_size_array)
{
    int            ret;
    zval          *buf;
    HashTable     *v;
#if PHP_VERSION_ID >= 70000
    zval           res;
#else
    zval          *res;
#endif
    long           size;
    unsigned long  i;
    unsigned long  len;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    struct sizer_callback_args args;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fh",
            &fci, &fci_cache, &v);
    if (ret == FAILURE)
        RETURN_FALSE;

    len = zend_hash_num_elements(v);

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;

    for (i = 0, size = 0; i < len; i++) {
#if PHP_VERSION_ID >= 70000
        args.val = zend_hash_index_find(v, i);
#else
        zval **val;
        zend_hash_index_find(v, i, (void **)&val);
        args.val = *val;
#endif
        size += sizer_callback(&args);
    }

    RETURN_LONG(size);
}

PHP_FUNCTION(bin_size_hashtbl)
{
    int            ret;
    zval          *buf;
    HashTable     *arg;
#if PHP_VERSION_ID >= 70000
    zval           kres;
    zval           vres;
#else
    zval          *kres;
    zval          *vres;
#endif
    long           size;
    unsigned long  i;
    unsigned long  len;

    zend_fcall_info kfci;
    zend_fcall_info_cache kfci_cache;

    zend_fcall_info vfci;
    zend_fcall_info_cache vfci_cache;

    struct sizer_callback_args kargs;
    struct sizer_callback_args vargs;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffh",
            &kfci, &kfci_cache, &vfci, &vfci_cache, &arg);
    if (ret == FAILURE)
        RETURN_FALSE;

    len = zend_hash_num_elements(arg);

#if PHP_VERSION_ID >= 70000
    kfci.retval = &kres;
    vfci.retval = &vres;
#else
    kfci.retval_ptr_ptr = &kres;
    vfci.retval_ptr_ptr = &vres;
#endif
    kargs.fci = &kfci;
    kargs.fci_cache = &kfci_cache;

    vargs.fci = &vfci;
    vargs.fci_cache = &vfci_cache;

    size = 0;
#if PHP_VERSION_ID >= 70000
    unsigned long index;
    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_KEY_VAL(arg, index, key, val) {
        zval k;
        if (key == NULL) {
            ZVAL_LONG(&k, index);
        } else {
            ZVAL_NEW_STR(&k, key);
        }
        kargs.val = &k;
        vargs.val = val;
        size += sizer_callback(&kargs);
        size += sizer_callback(&vargs);
    } ZEND_HASH_FOREACH_END();
#else
    HashPosition hpos;
    for (zend_hash_internal_pointer_reset_ex(arg, &hpos);
         zend_hash_has_more_elements_ex(arg, &hpos) == SUCCESS;
         zend_hash_move_forward_ex(arg, &hpos)) {
        char *key;
        unsigned int klen;
        unsigned long index;
        zval **val;
        zval k, v;
        switch (zend_hash_get_current_key_ex(arg, &key, &klen, &index, 0, &hpos)) {
        case HASH_KEY_IS_STRING:
            ZVAL_STRINGL(&k, key, klen - 1, 0);
            break;
        case HASH_KEY_IS_LONG:
            ZVAL_LONG(&k, index);
            break;
        default:
            RETURN_FALSE;
        }
        zend_hash_get_current_data_ex(arg, (void **)&val, &hpos);
        v = **val;
        kargs.val = &k;
        vargs.val = &v;
        size += sizer_callback(&kargs);
        size += sizer_callback(&vargs);
    }
#endif

    RETURN_LONG(size);
}


