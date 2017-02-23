#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define HAVE_SOCKETS 1

#include <php.h>
#include <php_ini.h>
#include <ext/standard/info.h>
#include <ext/sockets/php_sockets.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_closures.h>
#include <Zend/zend_variables.h>
#if PHP_VERSION_ID >= 70000
#include <Zend/zend_portability.h>
#endif

#include <bin_prot/read.h>
#include <bin_prot/write.h>
#include <bin_prot/size.h>
#include <bin_prot/type_class.h>
#include <bin_prot/rpc.h>

#include "php_bin_prot.h"

#define BIN_VERSION "0.0.1"
#define BIN_RPC     "Bin_RPC"
#define BIN_CONN    "Bin_RPC_Connection"

#define BIN_READ_NS      "bin_prot\\read"
#define BIN_WRITE_NS     "bin_prot\\write"
#define BIN_SIZE_NS      "bin_prot\\size"
#define BIN_TYPECLASS_NS "bin_prot\\type_class"
#define BIN_RPC_NS       "bin_prot\\rpc"

#if PHP_VERSION_ID >= 70000
#define SIZE_T size_t
#else
#define add_index_string(z, i, l) add_index_string(z, i, l, 0)
#define SIZE_T int
#endif

static void *
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

/*
 * Type classes
 */

#if PHP_VERSION_ID >= 70000
static void
hash_str_add_str(HashTable *ht, char *key, char *value)
{
    zval z;
    zend_string *zs;
    zs = zend_string_init(value, strlen(value), 1);
    ZVAL_STR(&z, zs);
    zend_hash_str_add_new(ht, key, strlen(key), &z);
}

#define DEFINE_TYPECLASS_CONST(type)                                  \
static void                                                           \
define_typeclass_const_##type(int module_number)                      \
{                                                                     \
    HashTable *ht;                                                    \
    char *const_name;                                                 \
    zend_constant c;                                                  \
                                                                      \
    ALLOC_HASHTABLE(ht);                                              \
    zend_hash_init(ht, 3, NULL, NULL, 0);                             \
                                                                      \
    hash_str_add_str(ht, "read",  BIN_READ_NS  "\\bin_read_"  #type); \
    hash_str_add_str(ht, "write", BIN_WRITE_NS "\\bin_write_" #type); \
    hash_str_add_str(ht, "size",  BIN_SIZE_NS  "\\bin_size_"  #type); \
                                                                      \
    ZVAL_ARR(&c.value, ht);                                           \
    const_name = BIN_TYPECLASS_NS "\\bin_" #type;                     \
    c.name = zend_string_init(const_name, strlen(const_name), 1);     \
    c.flags = CONST_PERSISTENT;                                       \
    c.module_number = module_number;                                  \
    zend_register_constant(&c);                                       \
}
#else
#define DEFINE_TYPECLASS_CONST(type)               \
static void                                        \
define_typeclass_const_##type(int module_number)   \
{                                                  \
    /* XXX PHP 5 won't allow const hash tables. */ \
}
#endif

DEFINE_TYPECLASS_CONST(unit)
DEFINE_TYPECLASS_CONST(bool)
DEFINE_TYPECLASS_CONST(char)

DEFINE_TYPECLASS_CONST(nat0)
DEFINE_TYPECLASS_CONST(int)
DEFINE_TYPECLASS_CONST(int32)
DEFINE_TYPECLASS_CONST(int64)

DEFINE_TYPECLASS_CONST(int_8bit)
DEFINE_TYPECLASS_CONST(int_16bit)
DEFINE_TYPECLASS_CONST(int_32bit)
DEFINE_TYPECLASS_CONST(int_64bit)

DEFINE_TYPECLASS_CONST(network16_int)
DEFINE_TYPECLASS_CONST(network32_int)
DEFINE_TYPECLASS_CONST(network64_int)

DEFINE_TYPECLASS_CONST(network16_int16)
DEFINE_TYPECLASS_CONST(network32_int32)
DEFINE_TYPECLASS_CONST(network64_int64)

DEFINE_TYPECLASS_CONST(variant_int)

DEFINE_TYPECLASS_CONST(float)

DEFINE_TYPECLASS_CONST(string)
DEFINE_TYPECLASS_CONST(digest)

/*
 * Read
 */

#define DEFINE_READER(name, c_type, php_type)                    \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_##name, 0, 0, 2)              \
    ZEND_ARG_INFO(0, buf)                                        \
    ZEND_ARG_INFO(0, pos)                                        \
ZEND_END_ARG_INFO();                                             \
                                                                 \
PHP_FUNCTION(bin_read_##name)                                    \
{                                                                \
    int     ret;                                                 \
    zval   *buf;                                                 \
    long    pos;                                                 \
	c_type  res;                                                 \
                                                                 \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", \
            &buf, &pos);                                         \
    if (ret == FAILURE)                                          \
        RETURN_FALSE;                                            \
                                                                 \
    ret = bin_read_##name(ptr_of_zval(buf), &pos, &res);         \
    if (ret == -1)                                               \
        RETURN_FALSE;                                            \
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
ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_##name, 0, 0, 2)              \
    ZEND_ARG_INFO(0, buf)                                        \
    ZEND_ARG_INFO(0, pos)                                        \
ZEND_END_ARG_INFO();                                             \
                                                                 \
PHP_FUNCTION(bin_read_##name)                                    \
{                                                                \
    int     ret;                                                 \
    zval   *buf;                                                 \
    long    pos;                                                 \
	char   *res;                                                 \
                                                                 \
    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", \
            &buf, &pos);                                         \
    if (ret == FAILURE)                                          \
        RETURN_FALSE;                                            \
                                                                 \
    ret = bin_read_##name(ptr_of_zval(buf), &pos, &res);         \
    if (ret == -1)                                               \
        RETURN_FALSE;                                            \
                                                                 \
    array_init(return_value);                                    \
    ARRAY_ADD_STRING(return_value, 0, res);                      \
    add_index_long(return_value, 1, pos);                        \
    free(res);                                                   \
}

DEFINE_STRING_READER(string)
DEFINE_STRING_READER(digest)

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_unit, 0, 0, 2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

PHP_FUNCTION(bin_read_unit)
{
    int     ret;
    zval   *buf;
    long    pos;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", &buf, &pos);
    if (ret == FAILURE)
        RETURN_FALSE;

    ret = bin_read_unit(ptr_of_zval(buf), &pos, NULL);
    if (ret == -1)
        RETURN_FALSE;

	RETURN_LONG(pos);
}

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_char, 0, 0, 2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

PHP_FUNCTION(bin_read_char)
{
    int     ret;
    zval   *buf;
    long    pos;
    char    res[2];

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zl", &buf, &pos);
    if (ret == FAILURE)
        RETURN_FALSE;

    ret = bin_read_char(ptr_of_zval(buf), &pos, &res[0]);
    if (ret == -1)
        RETURN_FALSE;

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_option, 0, 0, 3)
    ZEND_ARG_INFO(0, reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

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
    if (ret == FAILURE)
        RETURN_FALSE;

#if PHP_VERSION_ID >= 70000
    fci.retval = &res;
#else
    fci.retval_ptr_ptr = &res;
#endif
    args.fci = &fci;
    args.fci_cache = &fci_cache;
    args.buf = buf;

    ret = bin_read_option(reader_callback, ptr_of_zval(buf), &pos, &args);
    if (ret == FAILURE)
        RETURN_FALSE;
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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_pair, 0, 0, 4)
    ZEND_ARG_INFO(0, reader1)
    ZEND_ARG_INFO(0, reader2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

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

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;

    ret = bin_read_pair(reader_callback, reader_callback,
                        ptr_of_zval(buf), &pos, &args1, &args2);
    if (ret == FAILURE)
        RETURN_FALSE;

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_triple, 0, 0, 5)
    ZEND_ARG_INFO(0, reader1)
    ZEND_ARG_INFO(0, reader2)
    ZEND_ARG_INFO(0, reader3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

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
            &fci1, &fci_cache1, &fci2, &fci_cache2, &fci3, &fci_cache3, &buf, &pos);
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

    args2.fci = &fci2;
    args2.fci_cache = &fci_cache2;
    args2.buf = buf;

    args3.fci = &fci3;
    args3.fci_cache = &fci_cache3;
    args3.buf = buf;

    ret = bin_read_triple(reader_callback, reader_callback, reader_callback,
                          ptr_of_zval(buf), &pos, &args1, &args2, &args3);
    if (ret == FAILURE)
        RETURN_FALSE;

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_array, 0, 0, 3)
    ZEND_ARG_INFO(0, reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

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
    if (ret == FAILURE)
        RETURN_FALSE;

    ret = bin_read_nat0(ptr_of_zval(buf), &pos, &len);
    if (ret == FAILURE)
        RETURN_FALSE;

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_hashtbl, 0, 0, 4)
    ZEND_ARG_INFO(0, key_reader)
    ZEND_ARG_INFO(0, val_reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

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
    if (ret == FAILURE)
        RETURN_FALSE;

    ret = bin_read_nat0(ptr_of_zval(buf), &pos, &len);
    if (ret == FAILURE)
        RETURN_FALSE;

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

/*
 * Write
 */

#define DEFINE_WRITER(name, c_type, php_param)                             \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_##name, 0, 0, 3)                       \
    ZEND_ARG_INFO(0, buf)                                                  \
    ZEND_ARG_INFO(0, pos)                                                  \
    ZEND_ARG_INFO(0, v)                                                    \
ZEND_END_ARG_INFO();                                                       \
                                                                           \
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
ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_##name, 0, 0, 3)              \
    ZEND_ARG_INFO(0, buf)                                         \
    ZEND_ARG_INFO(0, pos)                                         \
    ZEND_ARG_INFO(0, v)                                           \
ZEND_END_ARG_INFO();                                              \
                                                                  \
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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_unit, 0, 0, 3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, unused)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_char, 0, 0, 3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_option, 0, 0, 4)
    ZEND_ARG_INFO(0, writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_pair, 0, 0, 6)
    ZEND_ARG_INFO(0, writer1)
    ZEND_ARG_INFO(0, writer2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_triple, 0, 0, 8)
    ZEND_ARG_INFO(0, writer1)
    ZEND_ARG_INFO(0, writer2)
    ZEND_ARG_INFO(0, writer3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
    ZEND_ARG_INFO(0, v3)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_array, 0, 0, 4)
    ZEND_ARG_INFO(0, writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_hashtbl, 0, 0, 5)
    ZEND_ARG_INFO(0, key_writer)
    ZEND_ARG_INFO(0, val_writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

/*
 * Size
 */

#define DEFINE_SIZER(name, php_param)                                      \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_##name, 0, 0, 1)                        \
    ZEND_ARG_INFO(0, v)                                                    \
ZEND_END_ARG_INFO();                                                       \
                                                                           \
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
ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_##name, 0, 0, 1)                  \
    ZEND_ARG_INFO(0, v)                                              \
ZEND_END_ARG_INFO();                                                 \
                                                                     \
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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_unit, 0, 0, 1)
    ZEND_ARG_INFO(0, unused)
ZEND_END_ARG_INFO();

PHP_FUNCTION(bin_size_unit)
{
    RETURN_LONG(bin_size_unit(NULL));
}

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_char, 0, 0, 1)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_option, 0, 0, 2)
    ZEND_ARG_INFO(0, sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_pair, 0, 0, 4)
    ZEND_ARG_INFO(0, sizer1)
    ZEND_ARG_INFO(0, sizer2)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_triple, 0, 0, 6)
    ZEND_ARG_INFO(0, sizer1)
    ZEND_ARG_INFO(0, sizer2)
    ZEND_ARG_INFO(0, sizer3)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
    ZEND_ARG_INFO(0, v3)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_array, 0, 0, 2)
    ZEND_ARG_INFO(0, sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_hashtbl, 0, 0, 3)
    ZEND_ARG_INFO(0, key_sizer)
    ZEND_ARG_INFO(0, val_sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

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

/*
 * RPC
 */

static int le_rpc;
typedef struct _rpc_resource {
    struct bin_rpc *rpc;
} rpc_resource;

static int le_conn;
typedef struct _conn_resource {
    struct bin_rpc_connection *conn;
} conn_resource;

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_client, 0, 0, 2)
    ZEND_ARG_INFO(0, socket)
    ZEND_ARG_INFO(0, description)
ZEND_END_ARG_INFO();

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_create, 0, 0, 4)
    ZEND_ARG_INFO(0, tag)
    ZEND_ARG_INFO(0, version)
    ZEND_ARG_INFO(0, bin_query)
    ZEND_ARG_INFO(0, bin_response)
ZEND_END_ARG_INFO();

PHP_FUNCTION(bin_rpc_create)
{
    int        ret;
    char      *tag;
    SIZE_T     tag_len;
    long       version;
    HashTable *bin_query_ht;
    HashTable *bin_response_ht;
    zval      *z_query_reader,    *z_query_writer,    *z_query_sizer;
    zval      *z_response_reader, *z_response_writer, *z_response_sizer;

    struct bin_type_class_reader *query_reader;
    struct bin_type_class_writer *query_writer;
    struct bin_type_class        *bin_query;

    struct bin_type_class_reader *response_reader;
    struct bin_type_class_writer *response_writer;
    struct bin_type_class        *bin_response;

    struct bin_rpc *rpc;
    rpc_resource *rpc_res;

    ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slhh",
            &tag, &tag_len, &version, &bin_query_ht, &bin_response_ht);
    if (ret == FAILURE)
        RETURN_FALSE;

    ret = type_class_extract(bin_query_ht, &z_query_reader, &z_query_writer,
                             &z_query_sizer);
    if (ret == -1)
        RETURN_FALSE;

    ret = type_class_extract(bin_response_ht, &z_response_reader,
                             &z_response_writer, &z_response_sizer);
    if (ret == -1)
        RETURN_FALSE;

    query_reader = emalloc(sizeof(*query_reader));
    query_reader->read = read_wrapper;
    query_reader->read_data = z_query_reader;

    query_writer = emalloc(sizeof(*query_writer));
    query_writer->write = write_wrapper;
    query_writer->write_data = z_query_writer;
    query_writer->size = size_wrapper;
    query_writer->size_data = z_query_sizer;

    bin_query = emalloc(sizeof(*bin_query));
    bin_query->reader = query_reader;
    bin_query->writer = query_writer;

    response_reader = emalloc(sizeof(*response_reader));
    response_reader->read = read_wrapper;
    response_reader->read_data = z_response_reader;

    response_writer = emalloc(sizeof(*response_writer));
    response_writer->write = write_wrapper;
    response_writer->write_data = z_response_writer;
    response_writer->size = size_wrapper;
    response_writer->size_data = z_response_sizer;

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

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_dispatch, 0, 0, 3)
    ZEND_ARG_INFO(0, rpc)
    ZEND_ARG_INFO(0, connection)
    ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO();

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
    rpc_res = zend_fetch_resource(Z_RES_P(z_rpc_res), BIN_RPC, le_rpc);
    conn_res = zend_fetch_resource(Z_RES_P(z_conn_res), BIN_CONN, le_conn);
    ret = bin_rpc_dispatch(rpc_res->rpc, conn_res->conn, data, &res);
#else
    ZEND_FETCH_RESOURCE(rpc_res, rpc_resource *, &z_rpc_res, -1,
                        BIN_RPC, le_rpc);
    ZEND_FETCH_RESOURCE(conn_res, conn_resource *, &z_conn_res, -1,
                        BIN_CONN, le_conn);
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

const zend_function_entry bin_prot_functions[] = {
    /* Read */
    ZEND_NS_FE(BIN_READ_NS, bin_read_unit, ai_bin_read_unit)
    ZEND_NS_FE(BIN_READ_NS, bin_read_char, ai_bin_read_char)

    ZEND_NS_FE(BIN_READ_NS, bin_read_nat0,  ai_bin_read_nat0)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int,   ai_bin_read_int)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int32, ai_bin_read_int32)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int64, ai_bin_read_int64)

    ZEND_NS_FE(BIN_READ_NS, bin_read_int_8bit,  ai_bin_read_int_8bit)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int_16bit, ai_bin_read_int_16bit)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int_32bit, ai_bin_read_int_32bit)
    ZEND_NS_FE(BIN_READ_NS, bin_read_int_64bit, ai_bin_read_int_64bit)

    ZEND_NS_FE(BIN_READ_NS, bin_read_network16_int, ai_bin_read_network16_int)
    ZEND_NS_FE(BIN_READ_NS, bin_read_network32_int, ai_bin_read_network32_int)
    ZEND_NS_FE(BIN_READ_NS, bin_read_network64_int, ai_bin_read_network64_int)

    ZEND_NS_FE(BIN_READ_NS, bin_read_variant_int, ai_bin_read_variant_int)

    ZEND_NS_FE(BIN_READ_NS, bin_read_float,   ai_bin_read_float)
    ZEND_NS_FE(BIN_READ_NS, bin_read_string,  ai_bin_read_string)

    ZEND_NS_FE(BIN_READ_NS, bin_read_option,  ai_bin_read_option)

    ZEND_NS_FE(BIN_READ_NS, bin_read_pair,    ai_bin_read_pair)
    ZEND_NS_FE(BIN_READ_NS, bin_read_triple,  ai_bin_read_triple)

    ZEND_NS_FE(BIN_READ_NS, bin_read_array,   ai_bin_read_array)
    ZEND_NS_FE(BIN_READ_NS, bin_read_hashtbl, ai_bin_read_hashtbl)

    ZEND_NS_FE(BIN_READ_NS, bin_read_digest,  ai_bin_read_digest)

    /* Write */
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_unit, ai_bin_write_unit)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_char, ai_bin_write_char)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_nat0,  ai_bin_write_nat0)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int,   ai_bin_write_int)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int32, ai_bin_write_int32)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int64, ai_bin_write_int64)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int_8bit,  ai_bin_write_int_8bit)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int_16bit, ai_bin_write_int_16bit)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int_32bit, ai_bin_write_int_32bit)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_int_64bit, ai_bin_write_int_64bit)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_network16_int, ai_bin_write_network16_int)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_network32_int, ai_bin_write_network32_int)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_network64_int, ai_bin_write_network64_int)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_variant_int, ai_bin_write_variant_int)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_float,  ai_bin_read_float)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_string, ai_bin_read_string)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_option, ai_bin_write_option)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_pair,   ai_bin_write_pair)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_triple, ai_bin_write_triple)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_array,   ai_bin_write_array)
    ZEND_NS_FE(BIN_WRITE_NS, bin_write_hashtbl, ai_bin_write_hashtbl)

    ZEND_NS_FE(BIN_WRITE_NS, bin_write_digest, ai_bin_write_digest)

    /* Size */
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_unit,  ai_bin_read_unit)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_char,  ai_bin_read_char)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_nat0,  ai_bin_size_nat0)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int,   ai_bin_read_int)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int32, ai_bin_size_int32)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int64, ai_bin_size_int64)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int_8bit,  ai_bin_size_int_8bit)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int_16bit, ai_bin_size_int_16bit)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int_32bit, ai_bin_size_int_32bit)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_int_64bit, ai_bin_size_int_64bit)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_network16_int, ai_bin_size_network16_int)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_network32_int, ai_bin_size_network32_int)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_network64_int, ai_bin_size_network64_int)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_variant_int, ai_bin_size_variant_int)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_float,   ai_bin_size_float)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_string,  ai_bin_size_string)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_option,  ai_bin_size_option)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_pair,    ai_bin_size_pair)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_triple,  ai_bin_size_triple)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_array,   ai_bin_size_array)
    ZEND_NS_FE(BIN_SIZE_NS, bin_size_hashtbl, ai_bin_size_hashtbl)

    ZEND_NS_FE(BIN_SIZE_NS, bin_size_digest,  ai_bin_size_digest)

    /* RPC */
    ZEND_NS_FE(BIN_RPC_NS, bin_rpc_client,   ai_bin_rpc_client)
    ZEND_NS_FE(BIN_RPC_NS, bin_rpc_create,   ai_bin_rpc_create)
    ZEND_NS_FE(BIN_RPC_NS, bin_rpc_dispatch, ai_bin_rpc_dispatch)

	PHP_FE_END
};

zend_module_entry bin_prot_module_entry = {
	STANDARD_MODULE_HEADER,
	"bin_prot",
	bin_prot_functions,
	PHP_MINIT(binprot),
	PHP_MSHUTDOWN(binprot),
    NULL, /* PHP_RINIT(binprot) */
    NULL, /* PHP_RSHUTDOWN(binprot) */
	NULL,
	BIN_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_BIN_PROT
ZEND_GET_MODULE(bin_prot)
#endif

static void
rpc_resource_dtor(
#if PHP_VERSION_ID >= 70000
        zend_resource
#else
        zend_rsrc_list_entry
#endif
        *rsrc TSRMLS_DC)
{
    rpc_resource *r = (rpc_resource *)rsrc->ptr;
    efree(r->rpc->bin_query->reader);
    efree(r->rpc->bin_query->writer);
    efree(r->rpc->bin_query);
    efree(r->rpc->bin_response->reader);
    efree(r->rpc->bin_response->writer);
    efree(r->rpc->bin_response);
    efree(r->rpc->tag);
    efree(r->rpc);
    efree(r);
}

static void
conn_resource_dtor(
#if PHP_VERSION_ID >= 70000
        zend_resource
#else
        zend_rsrc_list_entry
#endif
        *rsrc TSRMLS_DC)
{
    conn_resource *c = (conn_resource *)rsrc->ptr;
    bin_rpc_connection_free(c->conn);
    efree(c);
}

PHP_MINIT_FUNCTION(binprot)
{
    define_typeclass_const_unit(module_number);
    define_typeclass_const_bool(module_number);
    define_typeclass_const_char(module_number);

    define_typeclass_const_nat0(module_number);
    define_typeclass_const_int(module_number);
    define_typeclass_const_int32(module_number);
    define_typeclass_const_int64(module_number);

    define_typeclass_const_int_8bit(module_number);
    define_typeclass_const_int_16bit(module_number);
    define_typeclass_const_int_32bit(module_number);
    define_typeclass_const_int_64bit(module_number);

    define_typeclass_const_network16_int(module_number);
    define_typeclass_const_network32_int(module_number);
    define_typeclass_const_network64_int(module_number);

    define_typeclass_const_network16_int16(module_number);
    define_typeclass_const_network32_int32(module_number);
    define_typeclass_const_network64_int64(module_number);

    define_typeclass_const_variant_int(module_number);

    define_typeclass_const_float(module_number);

    define_typeclass_const_string(module_number);
    define_typeclass_const_digest(module_number);

    le_rpc = zend_register_list_destructors_ex(rpc_resource_dtor, NULL,
                                               BIN_RPC, module_number);
    le_conn = zend_register_list_destructors_ex(conn_resource_dtor, NULL,
                                                BIN_CONN, module_number);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(binprot)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(binprot)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "bin_prot support", "enabled");
	php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
