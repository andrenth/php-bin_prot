#include <stdlib.h>

#include <php.h>
#include <Zend/zend_exceptions.h>

#include <bin_prot/write.h>

#include "php_bin_prot.h"
#include "bin_prot_common.h"

#define DEFINE_WRITER(name, c_type, php_param)                             \
PHP_FUNCTION(bin_write_##name)                                             \
{                                                                          \
    int     ret;                                                           \
    zval   *buf;                                                           \
    long    pos;                                                           \
    c_type  v;                                                             \
                                                                           \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl" php_param, \
            &buf, &pos, &v);                                               \
    if (ret == FAILURE)                                                    \
        RETURN_FALSE;                                                      \
                                                                           \
    RETURN_LONG(bin_write_##name(ptr_of_zval(buf), pos, v));               \
}

DEFINE_WRITER(nat0,          long,   "l")
DEFINE_WRITER(int,           long,   "l")
DEFINE_WRITER(int32,         long,   "l")
DEFINE_WRITER(int64,         long,   "l")
DEFINE_WRITER(int_8bit,      long,   "l")
DEFINE_WRITER(int_16bit,     long,   "l")
DEFINE_WRITER(int_32bit,     long,   "l")
DEFINE_WRITER(int_64bit,     long,   "l")
DEFINE_WRITER(network16_int, long,   "l")
DEFINE_WRITER(network32_int, long,   "l")
DEFINE_WRITER(network64_int, long,   "l")
DEFINE_WRITER(variant_int,   long,   "l")
DEFINE_WRITER(float,         double, "d")

#define DEFINE_STRING_WRITER(name)                                \
PHP_FUNCTION(bin_write_##name)                                    \
{                                                                 \
    int     ret;                                                  \
    zval   *buf;                                                  \
    char   *v;                                                    \
    SIZE_T  v_len;                                                \
    long    pos;                                                  \
                                                                  \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zls", \
            &buf, &pos, &v, &v_len);                              \
    if (ret == FAILURE)                                           \
        RETURN_FALSE;                                             \
                                                                  \
    RETURN_LONG(bin_write_##name(ptr_of_zval(buf), pos, v));      \
}

DEFINE_STRING_WRITER(string)
DEFINE_STRING_WRITER(digest)

PHP_FUNCTION(bin_write_unit)
{
    int     ret;
    zval   *buf;
    long    pos;
    zval   *unused;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zlz",
            &buf, &pos, &unused);
    if (ret == FAILURE)
        RETURN_FALSE;

    RETURN_LONG(bin_write_unit(ptr_of_zval(buf), pos, NULL));
}

PHP_FUNCTION(bin_write_char)
{
    int     ret;
    zval   *buf;
    char   *v;
#if PHP_VERSION_ID >= 70000
    size_t  v_len;
#else
	int     v_len;
#endif
    long    pos;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zls",
            &buf, &pos, &v, &v_len);
    if (ret == FAILURE)
        RETURN_FALSE;

    RETURN_LONG(bin_write_char(ptr_of_zval(buf), pos, v[0]));
}

struct writer_callback_args {
    zend_fcall_info       *fci;
    zend_fcall_info_cache *fci_cache;
	zval				  *buf;
    zval                  *val;
};

static size_t
writer_callback(void *_buf, size_t pos, void *arg)
{
    struct writer_callback_args *args = (struct writer_callback_args *)arg;

#if PHP_VERSION_ID >= 70000
    zval params[3];
    ZVAL_ZVAL(&params[0], args->buf, 0, 0);
    ZVAL_LONG(&params[1], pos);
    ZVAL_ZVAL(&params[2], args->val, 0, 0);
#else
    zval ***params = safe_emalloc(3, sizeof(zval **), 0);
    zval *zpos = emalloc(sizeof(zval));
    ZVAL_LONG(zpos, pos);
    params[0] = &args->buf;
    params[1] = &zpos;
    params[2] = &args->val;
#endif
    args->fci->params = params;
    args->fci->param_count = 3;

    zend_call_function(args->fci, args->fci_cache);

#if PHP_VERSION_ID >= 70000
    return Z_LVAL_P(args->fci->retval);
#else
    efree(zpos);
    efree(params);
    return Z_LVAL_P(*args->fci->retval_ptr_ptr);
#endif
}

PHP_FUNCTION(bin_write_option)
{
    int     ret;
    zval   *buf;
    zval   *v;
#if PHP_VERSION_ID >= 70000
    zval    res;
#else
    zval   *res;
#endif
    long    pos;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    struct writer_callback_args args;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fzlz",
            &fci, &fci_cache, &buf, &pos, &v);
    if (ret == FAILURE)
        RETURN_FALSE;

    if (Z_TYPE_P(v) == IS_NULL) {
        pos = bin_write_option(writer_callback, ptr_of_zval(buf), pos, NULL);
        RETURN_LONG(pos);
    }

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.buf = buf;
    args.val = v;

    RETURN_LONG(bin_write_option(writer_callback, ptr_of_zval(buf), pos, &args));
}

PHP_FUNCTION(bin_write_pair)
{
    int     ret;
    zval   *buf;
    zval   *v1;
    zval   *v2;
#if PHP_VERSION_ID >= 70000
    zval    res1;
    zval    res2;
#else
    zval   *res1;
    zval   *res2;
#endif
    long    pos;

    struct writer_callback_args args1;
    struct writer_callback_args args2;

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffzlzz",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &buf, &pos, &v1, &v2);
    if (ret == FAILURE)
        RETURN_FALSE;

#if PHP_VERSION_ID >= 70000
    fci1.retval = &res1;
    fci2.retval = &res2;
#else
    fci1.retval_ptr_ptr = &res1;
    fci2.retval_ptr_ptr = &res2;
#endif
    args1.fci = &fci1;
    args1.fci_cache = &fci_cache1;
    args1.buf = buf;
    args1.val = v1;

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;
    args2.val = v2;

    RETURN_LONG(bin_write_pair(writer_callback, writer_callback,
                               ptr_of_zval(buf), pos, &args1, &args2));
}

PHP_FUNCTION(bin_write_triple)
{
    int     ret;
    zval   *buf;
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
    long    pos;

    struct writer_callback_args args1;
    struct writer_callback_args args2;
    struct writer_callback_args args3;

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    zend_fcall_info fci3;
    zend_fcall_info_cache fci_cache3;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fffzlzzz",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &fci3, &fci_cache3,
            &buf, &pos, &v1, &v2, &v3);
    if (ret == FAILURE)
        RETURN_FALSE;

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
    args1.buf = buf;
    args1.val = v1;

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;
    args2.val = v2;

    args3.fci = &fci3;
    args3.fci_cache = &fci_cache3;
    args3.buf = buf;
    args3.val = v3;

    RETURN_LONG(bin_write_triple(writer_callback,
                                 writer_callback,
                                 writer_callback,
                                 ptr_of_zval(buf), pos, &args1, &args2, &args3));
}

PHP_FUNCTION(bin_write_array)
{
    int            ret;
    zval          *buf;
    HashTable     *v;
#if PHP_VERSION_ID >= 70000
    zval           res;
#else
    zval          *res;
#endif
    long           pos;
    unsigned long  i;
    unsigned long  len;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    struct writer_callback_args args;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fzlh",
            &fci, &fci_cache, &buf, &pos, &v);
    if (ret == FAILURE)
        RETURN_FALSE;

    len = zend_hash_num_elements(v);
    pos = bin_write_nat0(ptr_of_zval(buf), pos, len);

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.buf = buf;

    for (i = 0; i < len; i++) {
#if PHP_VERSION_ID >= 70000
        args.val = zend_hash_index_find(v, i);
#else
        zval **val;
        zend_hash_index_find(v, i, (void **)&val);
        args.val = *val;
#endif
        pos = writer_callback(NULL, pos, &args);
    }

    RETURN_LONG(pos);
}

PHP_FUNCTION(bin_write_hashtbl)
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
    long           pos;
    unsigned long  i;
    unsigned long  len;

    zend_fcall_info kfci;
    zend_fcall_info_cache kfci_cache;

    zend_fcall_info vfci;
    zend_fcall_info_cache vfci_cache;

    struct writer_callback_args kargs;
    struct writer_callback_args vargs;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffzlh",
            &kfci, &kfci_cache, &vfci, &vfci_cache, &buf, &pos, &arg);
    if (ret == FAILURE)
        RETURN_FALSE;

    len = zend_hash_num_elements(arg);
    pos = bin_write_nat0(ptr_of_zval(buf), pos, len);

#if PHP_VERSION_ID >= 70000
    kfci.retval = &kres;
    vfci.retval = &vres;
#else
    kfci.retval_ptr_ptr = &kres;
    vfci.retval_ptr_ptr = &vres;
#endif
    kargs.fci = &kfci;
    kargs.fci_cache = &kfci_cache;
    kargs.buf = buf;

    vargs.fci = &vfci;
    vargs.fci_cache = &vfci_cache;
    vargs.buf = buf;

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
        pos = writer_callback(NULL, pos, &kargs);
        pos = writer_callback(NULL, pos, &vargs);
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
        pos = writer_callback(NULL, pos, &kargs);
        pos = writer_callback(NULL, pos, &vargs);
    }
#endif

    RETURN_LONG(pos);
}
