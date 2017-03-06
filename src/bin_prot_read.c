#include <stdlib.h>

#include <php.h>
#include <Zend/zend_exceptions.h>

#include <bin_prot/read.h>

#include "php_bin_prot.h"
#include "bin_prot_common.h"

#define DEFINE_READER(name, c_type, php_type)                    \
PHP_FUNCTION(bin_read_##name)                                    \
{                                                                \
    int     ret;                                                 \
    zval   *buf;                                                 \
    long    pos;                                                 \
	c_type  res;                                                 \
                                                                 \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", \
            &buf, &pos);                                         \
    if (ret == FAILURE) {                                        \
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_" # name);    \
        RETURN_FALSE;                                            \
    }                                                            \
                                                                 \
    ret = bin_read_##name(ptr_of_zval(buf), &pos, &res);         \
    if (ret == -1) {                                             \
        bin_throw(BIN_ERROR_READ, "bin_read_" # name);           \
        RETURN_FALSE;                                            \
    }                                                            \
                                                                 \
    array_init(return_value);                                    \
    add_index_##php_type(return_value, 0, res);                  \
    add_index_long(return_value, 1, pos);                        \
}

DEFINE_READER(nat0,          unsigned long, long)
DEFINE_READER(int,           long,          long)
DEFINE_READER(int32,         int32_t,       long)
DEFINE_READER(int64,         int64_t,       long)
DEFINE_READER(int_8bit,      long,          long)
DEFINE_READER(int_16bit,     long,          long)
DEFINE_READER(int_32bit,     long,          long)
DEFINE_READER(int_64bit,     long,          long)
DEFINE_READER(network16_int, long,          long)
DEFINE_READER(network32_int, long,          long)
DEFINE_READER(network64_int, long,          long)
DEFINE_READER(variant_int,   long,          long)
DEFINE_READER(float,         double,        double)

#if PHP_VERSION_ID >= 70000
#define ARRAY_ADD_STRING(a, i, s) add_index_string(a, i, s)
#else
#define ARRAY_ADD_STRING(a, i, s) add_index_stringl(a, i, s, strlen(s), 1)
#endif

#define DEFINE_STRING_READER(name)                               \
PHP_FUNCTION(bin_read_##name)                                    \
{                                                                \
    int     ret;                                                 \
    zval   *buf;                                                 \
    long    pos;                                                 \
	char   *res;                                                 \
                                                                 \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", \
            &buf, &pos);                                         \
    if (ret == FAILURE) {                                        \
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_" # name);    \
        RETURN_FALSE;                                            \
    }                                                            \
                                                                 \
    ret = bin_read_##name(ptr_of_zval(buf), &pos, &res);         \
    if (ret == -1) {                                             \
        bin_throw(BIN_ERROR_READ, "bin_read_" # name);           \
        RETURN_FALSE;                                            \
    }                                                            \
                                                                 \
    array_init(return_value);                                    \
    ARRAY_ADD_STRING(return_value, 0, res);                      \
    add_index_long(return_value, 1, pos);                        \
    free(res);                                                   \
}

DEFINE_STRING_READER(string)
DEFINE_STRING_READER(digest)

PHP_FUNCTION(bin_read_unit)
{
    int     ret;
    zval   *buf;
    long    pos;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_unit");
        RETURN_FALSE;
    }

    ret = bin_read_unit(ptr_of_zval(buf), &pos, NULL);
    if (ret == -1) {
        bin_throw(BIN_ERROR_READ, "bin_read_unit");
        RETURN_FALSE;
    }

	RETURN_LONG(pos);
}

PHP_FUNCTION(bin_read_char)
{
    int     ret;
    zval   *buf;
    long    pos;
    char    res[2];

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_char");
        RETURN_FALSE;
    }

    ret = bin_read_char(ptr_of_zval(buf), &pos, &res[0]);
    if (ret == -1) {
        bin_throw(BIN_ERROR_READ, "bin_read_char");
        RETURN_FALSE;
    }

    res[1] = '\0';
    array_init(return_value);
    add_index_string(return_value, 0, res);
    add_index_long(return_value, 1, pos);
}

struct reader_callback_args {
    zend_fcall_info       *fci;
    zend_fcall_info_cache *fci_cache;
    zval                  *buf;
};

static int
reader_callback(void *buf, size_t *pos, void *arg)
{
    int ret;
    struct reader_callback_args *args = (struct reader_callback_args *)arg;

#if PHP_VERSION_ID >= 70000
    zval params[2];
    params[0] = *args->buf;
    ZVAL_LONG(&params[1], *pos);
#else
    zval ***params = safe_emalloc(2, sizeof(zval **), 0);
    zval *zpos = emalloc(sizeof(zval *));
    ZVAL_LONG(zpos, *pos);
    params[0] = &args->buf;
    params[1] = &zpos;
#endif
    args->fci->params = params;
    args->fci->param_count = 2;

    ret = zend_call_function(args->fci, args->fci_cache);

#if PHP_VERSION_ID < 70000
    efree(zpos);
    efree(params);
#endif
    if (ret == FAILURE)
        return FAILURE;

#if PHP_VERSION_ID >= 70000
    zval *res = args->fci->retval;
    HashTable *ht = Z_ARRVAL_P(res);
    zval *new_pos = zend_hash_index_find(ht, 1);
    *pos = Z_LVAL_P(new_pos);
#else
    zval **res = args->fci->retval_ptr_ptr;
    HashTable *ht = Z_ARRVAL_P(*res);
    zval **new_pos;
    zend_hash_index_find(ht, 1, (void **)&new_pos);
    *pos = Z_LVAL_P(*new_pos);
#endif

    return ret;
}

PHP_FUNCTION(bin_read_option)
{
    int     ret;
    zval   *buf;
#if PHP_VERSION_ID >= 70000
    zval    res;
#else
    zval   *res;
#endif
    long    pos;

    struct reader_callback_args args;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fzl",
            &fci, &fci_cache, &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_option");
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.buf = buf;

    ret = bin_read_option(reader_callback, ptr_of_zval(buf), &pos, &args);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_READ, "bin_read_option");
        RETURN_FALSE;
    }

    if (ret == 0) { /* None */
        array_init(return_value);
        add_index_null(return_value, 0);
        add_index_long(return_value, 1, pos);
        return;
    }

#if PHP_VERSION_ID >= 70000
    RETURN_ZVAL(&res, 0, 0);
#else
    RETURN_ZVAL(res, 0, 0);
#endif
}

PHP_FUNCTION(bin_read_pair)
{
    int     ret;
    zval   *buf;
#if PHP_VERSION_ID >= 70000
    zval    res1;
    zval    res2;
#else
    zval   *res1;
    zval   *res2;
#endif
    long    pos;

    struct reader_callback_args args1;
    struct reader_callback_args args2;

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffzl",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_pair");
        RETURN_FALSE;
    }

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

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;

    ret = bin_read_pair(reader_callback, reader_callback,
                        ptr_of_zval(buf), &pos, &args1, &args2);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_READ, "bin_read_pair");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_index_null(return_value, 0);

#if PHP_VERSION_ID >= 70000
    HashTable *ht1 = Z_ARRVAL_P(&res1);
    HashTable *ht2 = Z_ARRVAL_P(&res2);
    zval *r1 = zend_hash_index_find(ht1, 0);
    zval *r2 = zend_hash_index_find(ht2, 0);
    add_index_zval(return_value, 0, r1);
    add_index_zval(return_value, 1, r2);
#else
    HashTable *ht1 = Z_ARRVAL_P(res1);
    HashTable *ht2 = Z_ARRVAL_P(res2);
    zval **r1;
    zval **r2;
    zend_hash_index_find(ht1, 0, (void **)&r1);
    zend_hash_index_find(ht2, 0, (void **)&r2);
    add_index_zval(return_value, 0, *r1);
    add_index_zval(return_value, 1, *r2);
#endif
    add_index_long(return_value, 2, pos);
}

PHP_FUNCTION(bin_read_triple)
{
    int     ret;
    zval   *buf;
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

    struct reader_callback_args args1;
    struct reader_callback_args args2;
    struct reader_callback_args args3;

    zend_fcall_info fci1;
    zend_fcall_info_cache fci_cache1;

    zend_fcall_info fci2;
    zend_fcall_info_cache fci_cache2;

    zend_fcall_info fci3;
    zend_fcall_info_cache fci_cache3;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fffzl",
            &fci1, &fci_cache1, &fci2, &fci_cache2, &fci3, &fci_cache3,
            &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_triple");
        RETURN_FALSE;
    }

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

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;

    args3.fci = &fci3;
    args3.fci_cache = &fci_cache3;
    args3.buf = buf;

    ret = bin_read_triple(reader_callback, reader_callback, reader_callback,
                          ptr_of_zval(buf), &pos, &args1, &args2, &args3);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_READ, "bin_read_triple");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_index_null(return_value, 0);

#if PHP_VERSION_ID >= 70000
    HashTable *ht1 = Z_ARRVAL_P(&res1);
    HashTable *ht2 = Z_ARRVAL_P(&res2);
    HashTable *ht3 = Z_ARRVAL_P(&res3);
    zval *r1 = zend_hash_index_find(ht1, 0);
    zval *r2 = zend_hash_index_find(ht2, 0);
    zval *r3 = zend_hash_index_find(ht3, 0);
    add_index_zval(return_value, 0, r1);
    add_index_zval(return_value, 1, r2);
    add_index_zval(return_value, 2, r3);
#else
    HashTable *ht1 = Z_ARRVAL_P(res1);
    HashTable *ht2 = Z_ARRVAL_P(res2);
    HashTable *ht3 = Z_ARRVAL_P(res3);
    zval **r1;
    zval **r2;
    zval **r3;
    zend_hash_index_find(ht1, 0, (void **)&r1);
    zend_hash_index_find(ht2, 0, (void **)&r2);
    zend_hash_index_find(ht3, 0, (void **)&r3);
    add_index_zval(return_value, 0, *r1);
    add_index_zval(return_value, 1, *r2);
    add_index_zval(return_value, 2, *r3);
#endif
    add_index_long(return_value, 3, pos);
}

PHP_FUNCTION(bin_read_array)
{
    int     ret;
    zval   *buf;
    long    pos;
    size_t  i;
    size_t  len;
#if PHP_VERSION_ID >= 70000
    zval    res;
    zval    array;
#else
    zval   *res;
    zval   *array;
    MAKE_STD_ZVAL(array);
#endif

    struct reader_callback_args args;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fzl",
            &fci, &fci_cache, &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_array");
        RETURN_FALSE;
    }

    ret = bin_read_nat0(ptr_of_zval(buf), &pos, &len);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_READ, "bin_read_array");
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
    array_init_size(&array, len);
#else
    fci.retval_ptr_ptr = &res;
    array_init_size(array, len);
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.buf = buf;

    for (i = 0; i < len; i++) {
        reader_callback(buf, &pos, &args);
#if PHP_VERSION_ID >= 70000
        HashTable *ht = Z_ARRVAL_P(&res);
        zval *r = zend_hash_index_find(ht, 0);
        add_index_zval(&array, i, r);
#else
        HashTable *ht = Z_ARRVAL_P(res);
        zval **r;
        zend_hash_index_find(ht, 0, (void **)&r);
        add_index_zval(array, i, *r);
#endif
    }

    array_init(return_value);

#if PHP_VERSION_ID >= 70000
    add_index_zval(return_value, 0, &array);
#else
    add_index_zval(return_value, 0, array);
#endif
    add_index_long(return_value, 1, pos);
}

PHP_FUNCTION(bin_read_list)
{
    zif_bin_read_array(execute_data, return_value);
}

PHP_FUNCTION(bin_read_hashtbl)
{
    int     ret;
    zval   *buf;
    long    pos;
    size_t  i;
    size_t  len;
#if PHP_VERSION_ID >= 70000
    zval    vres;
    zval    kres;
    zval    hashtbl;
#else
    zval   *vres;
    zval   *kres;
    zval   *hashtbl;
    MAKE_STD_ZVAL(hashtbl);
#endif

    struct reader_callback_args kargs;
    struct reader_callback_args vargs;

    zend_fcall_info kfci;
    zend_fcall_info_cache kfci_cache;

    zend_fcall_info vfci;
    zend_fcall_info_cache vfci_cache;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ffzl",
            &kfci, &kfci_cache, &vfci, &vfci_cache, &buf, &pos);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_INVALID_ARG, "bin_read_hashtbl");
        RETURN_FALSE;
    }

    ret = bin_read_nat0(ptr_of_zval(buf), &pos, &len);
    if (ret == FAILURE) {
        bin_throw(BIN_ERROR_READ, "bin_read_hashtbl");
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 70000
    kfci.retval = &kres;
    vfci.retval = &vres;
    array_init_size(&hashtbl, len);
#else
    kfci.retval_ptr_ptr = &kres;
    vfci.retval_ptr_ptr = &vres;
    array_init_size(hashtbl, len);
#endif
    kargs.fci = &kfci;
    kargs.fci_cache = &kfci_cache;
    kargs.buf = buf;

    vargs.fci = &vfci;
    vargs.fci_cache = &vfci_cache;
    vargs.buf = buf;

    for (i = 0; i < len; i++) {
        reader_callback(buf, &pos, &kargs);
        reader_callback(buf, &pos, &vargs);
#if PHP_VERSION_ID >= 70000
        HashTable *kht = Z_ARRVAL_P(&kres);
        HashTable *vht = Z_ARRVAL_P(&vres);
        zval *kr = zend_hash_index_find(kht, 0);
        zval *vr = zend_hash_index_find(vht, 0);
        add_assoc_zval(&hashtbl, Z_STRVAL_P(kr), vr);
#else
        HashTable *kht = Z_ARRVAL_P(kres);
        HashTable *vht = Z_ARRVAL_P(vres);
        zval **kr;
        zval **vr;
        zend_hash_index_find(kht, 0, (void **)&kr);
        zend_hash_index_find(vht, 0, (void **)&vr);
        add_assoc_zval(hashtbl, Z_STRVAL_PP(kr), *vr);
#endif
    }

    array_init(return_value);

#if PHP_VERSION_ID >= 70000
    add_index_zval(return_value, 0, &hashtbl);
#else
    add_index_zval(return_value, 0, hashtbl);
#endif
    add_index_long(return_value, 1, pos);
}
