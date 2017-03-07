#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define HAVE_SOCKETS 1

#include <php.h>
#include <ext/standard/info.h>
#include <ext/spl/spl_exceptions.h>

#include <bin_prot/type_class.h>
#include <bin_prot/rpc.h>

#include "php_bin_prot.h"
#include "bin_prot_common.h"

int le_rpc;
int le_conn;

zend_class_entry *bin_exn_read;
zend_class_entry *bin_exn_rpc;
zend_class_entry *bin_exn_invalid_arg;
zend_class_entry *bin_exn_sum_tag;
zend_class_entry *bin_exn_variant;

/*
 * Type classes
 */

#define DEFINE_READER_AI(name)                      \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_##name, 0, 0, 2) \
    ZEND_ARG_INFO(0, buf)                           \
    ZEND_ARG_INFO(0, pos)                           \
ZEND_END_ARG_INFO();

DEFINE_READER_AI(nat0)
DEFINE_READER_AI(int)
DEFINE_READER_AI(int32)
DEFINE_READER_AI(int64)
DEFINE_READER_AI(int_8bit)
DEFINE_READER_AI(int_16bit)
DEFINE_READER_AI(int_32bit)
DEFINE_READER_AI(int_64bit)
DEFINE_READER_AI(network16_int)
DEFINE_READER_AI(network32_int)
DEFINE_READER_AI(network64_int)
DEFINE_READER_AI(variant_int)
DEFINE_READER_AI(float)
DEFINE_READER_AI(string)
DEFINE_READER_AI(digest)

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_unit, 0, 0, 2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_char, 0, 0, 2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_option, 0, 0, 3)
    ZEND_ARG_INFO(0, reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_pair, 0, 0, 4)
    ZEND_ARG_INFO(0, reader1)
    ZEND_ARG_INFO(0, reader2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_triple, 0, 0, 5)
    ZEND_ARG_INFO(0, reader1)
    ZEND_ARG_INFO(0, reader2)
    ZEND_ARG_INFO(0, reader3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_array, 0, 0, 3)
    ZEND_ARG_INFO(0, reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_list, 0, 0, 3)
    ZEND_ARG_INFO(0, reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_read_hashtbl, 0, 0, 4)
    ZEND_ARG_INFO(0, key_reader)
    ZEND_ARG_INFO(0, val_reader)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
ZEND_END_ARG_INFO();

#define DEFINE_WRITER_AI(name)                       \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_##name, 0, 0, 3) \
    ZEND_ARG_INFO(0, buf)                            \
    ZEND_ARG_INFO(0, pos)                            \
    ZEND_ARG_INFO(0, v)                              \
ZEND_END_ARG_INFO();

DEFINE_WRITER_AI(nat0)
DEFINE_WRITER_AI(int)
DEFINE_WRITER_AI(int32)
DEFINE_WRITER_AI(int64)
DEFINE_WRITER_AI(int_8bit)
DEFINE_WRITER_AI(int_16bit)
DEFINE_WRITER_AI(int_32bit)
DEFINE_WRITER_AI(int_64bit)
DEFINE_WRITER_AI(network16_int)
DEFINE_WRITER_AI(network32_int)
DEFINE_WRITER_AI(network64_int)
DEFINE_WRITER_AI(variant_int)
DEFINE_WRITER_AI(float)
DEFINE_WRITER_AI(string)
DEFINE_WRITER_AI(digest)

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_array, 0, 0, 4)
    ZEND_ARG_INFO(0, writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_list, 0, 0, 4)
    ZEND_ARG_INFO(0, writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_hashtbl, 0, 0, 5)
    ZEND_ARG_INFO(0, key_writer)
    ZEND_ARG_INFO(0, val_writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_unit, 0, 0, 3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, unused)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_char, 0, 0, 3)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_option, 0, 0, 4)
    ZEND_ARG_INFO(0, writer)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_write_pair, 0, 0, 6)
    ZEND_ARG_INFO(0, writer1)
    ZEND_ARG_INFO(0, writer2)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(0, pos)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
ZEND_END_ARG_INFO();

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

#define DEFINE_SIZER_AI(name)                       \
ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_##name, 0, 0, 1) \
    ZEND_ARG_INFO(0, v)                             \
ZEND_END_ARG_INFO();

DEFINE_SIZER_AI(nat0)
DEFINE_SIZER_AI(int)
DEFINE_SIZER_AI(int32)
DEFINE_SIZER_AI(int64)
DEFINE_SIZER_AI(int_8bit)
DEFINE_SIZER_AI(int_16bit)
DEFINE_SIZER_AI(int_32bit)
DEFINE_SIZER_AI(int_64bit)
DEFINE_SIZER_AI(network16_int)
DEFINE_SIZER_AI(network32_int)
DEFINE_SIZER_AI(network64_int)
DEFINE_SIZER_AI(variant_int)
DEFINE_SIZER_AI(float)
DEFINE_SIZER_AI(string)
DEFINE_SIZER_AI(digest)

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_unit, 0, 0, 1)
    ZEND_ARG_INFO(0, unused)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_char, 0, 0, 1)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_option, 0, 0, 2)
    ZEND_ARG_INFO(0, sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_pair, 0, 0, 4)
    ZEND_ARG_INFO(0, sizer1)
    ZEND_ARG_INFO(0, sizer2)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_triple, 0, 0, 6)
    ZEND_ARG_INFO(0, sizer1)
    ZEND_ARG_INFO(0, sizer2)
    ZEND_ARG_INFO(0, sizer3)
    ZEND_ARG_INFO(0, v1)
    ZEND_ARG_INFO(0, v2)
    ZEND_ARG_INFO(0, v3)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_array, 0, 0, 2)
    ZEND_ARG_INFO(0, sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_list, 0, 0, 2)
    ZEND_ARG_INFO(0, sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_size_hashtbl, 0, 0, 3)
    ZEND_ARG_INFO(0, key_sizer)
    ZEND_ARG_INFO(0, val_sizer)
    ZEND_ARG_INFO(0, v)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_client, 0, 0, 2)
    ZEND_ARG_INFO(0, socket)
    ZEND_ARG_INFO(0, description)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_create, 0, 0, 4)
    ZEND_ARG_INFO(0, tag)
    ZEND_ARG_INFO(0, version)
    ZEND_ARG_INFO(0, bin_query)
    ZEND_ARG_INFO(0, bin_response)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_bin_rpc_dispatch, 0, 0, 3)
    ZEND_ARG_INFO(0, rpc)
    ZEND_ARG_INFO(0, connection)
    ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO();

const zend_function_entry binprot_functions[] = {
    /* Read */
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_unit, ai_bin_read_unit)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_char, ai_bin_read_char)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_nat0,  ai_bin_read_nat0)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int,   ai_bin_read_int)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int32, ai_bin_read_int32)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int64, ai_bin_read_int64)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int_8bit,  ai_bin_read_int_8bit)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int_16bit, ai_bin_read_int_16bit)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int_32bit, ai_bin_read_int_32bit)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_int_64bit, ai_bin_read_int_64bit)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_network16_int, ai_bin_read_network16_int)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_network32_int, ai_bin_read_network32_int)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_network64_int, ai_bin_read_network64_int)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_variant_int, ai_bin_read_variant_int)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_float,   ai_bin_read_float)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_string,  ai_bin_read_string)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_option,  ai_bin_read_option)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_pair,    ai_bin_read_pair)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_triple,  ai_bin_read_triple)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_array,   ai_bin_read_array)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_list,    ai_bin_read_list)
    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_hashtbl, ai_bin_read_hashtbl)

    ZEND_NS_FE(PHP_BIN_READ_NS, bin_read_digest,  ai_bin_read_digest)

    /* Write */
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_unit, ai_bin_write_unit)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_char, ai_bin_write_char)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_nat0,  ai_bin_write_nat0)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int,   ai_bin_write_int)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int32, ai_bin_write_int32)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int64, ai_bin_write_int64)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int_8bit,  ai_bin_write_int_8bit)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int_16bit, ai_bin_write_int_16bit)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int_32bit, ai_bin_write_int_32bit)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_int_64bit, ai_bin_write_int_64bit)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_network16_int, ai_bin_write_network16_int)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_network32_int, ai_bin_write_network32_int)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_network64_int, ai_bin_write_network64_int)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_variant_int, ai_bin_write_variant_int)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_float,  ai_bin_read_float)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_string, ai_bin_read_string)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_option, ai_bin_write_option)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_pair,   ai_bin_write_pair)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_triple, ai_bin_write_triple)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_array,   ai_bin_write_array)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_list,    ai_bin_write_list)
    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_hashtbl, ai_bin_write_hashtbl)

    ZEND_NS_FE(PHP_BIN_WRITE_NS, bin_write_digest, ai_bin_write_digest)

    /* Size */
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_unit,  ai_bin_read_unit)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_char,  ai_bin_read_char)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_nat0,  ai_bin_size_nat0)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int,   ai_bin_read_int)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int32, ai_bin_size_int32)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int64, ai_bin_size_int64)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int_8bit,  ai_bin_size_int_8bit)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int_16bit, ai_bin_size_int_16bit)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int_32bit, ai_bin_size_int_32bit)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_int_64bit, ai_bin_size_int_64bit)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_network16_int, ai_bin_size_network16_int)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_network32_int, ai_bin_size_network32_int)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_network64_int, ai_bin_size_network64_int)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_variant_int, ai_bin_size_variant_int)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_float,   ai_bin_size_float)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_string,  ai_bin_size_string)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_option,  ai_bin_size_option)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_pair,    ai_bin_size_pair)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_triple,  ai_bin_size_triple)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_array,   ai_bin_size_array)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_list,    ai_bin_size_list)
    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_hashtbl, ai_bin_size_hashtbl)

    ZEND_NS_FE(PHP_BIN_SIZE_NS, bin_size_digest,  ai_bin_size_digest)

    /* RPC */
    ZEND_NS_FE(PHP_BIN_RPC_NS, bin_rpc_client,   ai_bin_rpc_client)
    ZEND_NS_FE(PHP_BIN_RPC_NS, bin_rpc_create,   ai_bin_rpc_create)
    ZEND_NS_FE(PHP_BIN_RPC_NS, bin_rpc_dispatch, ai_bin_rpc_dispatch)

    PHP_FE_END
};

zend_module_entry binprot_module_entry = {
    STANDARD_MODULE_HEADER,
    "bin_prot",
    binprot_functions,
    PHP_MINIT(binprot),
    PHP_MSHUTDOWN(binprot),
    NULL, /* PHP_RINIT(binprot) */
    NULL, /* PHP_RSHUTDOWN(binprot) */
    NULL,
    PHP_BINPROT_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_BINPROT
ZEND_GET_MODULE(binprot)
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

static zend_function_entry bin_exn_functions[] = {
    PHP_FE_END
};


static void
define_exn(zend_class_entry *cep, zend_class_entry **exn, const char *name)
{
    zend_class_entry ce = *cep;

    INIT_CLASS_ENTRY(ce, name, bin_exn_functions);
    printf(">>>>>>>>>>>>>>>>>> definint class %s\n", name);
    *exn =
#if PHP_VERSION_ID >= 70000
        zend_register_internal_class_ex(&ce, spl_ce_InvalidArgumentException);
#else
        zend_register_internal_class_ex(&ce, spl_ce_InvalidArgumentException,
                                        NULL TSRMLS_CC);
#endif
}

#if PHP_VERSION_ID >= 70000
#define REGISTER_EXN(name, ce_name, class_name)                                \
static void                                                                    \
register_exn_##name()                                                          \
{                                                                              \
    zend_class_entry ce;                                                       \
                                                                               \
    INIT_CLASS_ENTRY(ce, class_name, bin_exn_functions);                       \
    ce_name =                                                                  \
        zend_register_internal_class_ex(&ce, spl_ce_InvalidArgumentException); \
}
#else
#define REGISTER_EXN(name, ce_name, class_name)                                \
static void                                                                    \
register_exn_##name()                                                          \
{                                                                              \
    zend_class_entry ce;                                                       \
                                                                               \
    INIT_CLASS_ENTRY(ce, class_name, bin_exn_functions);                       \
    ce_name =                                                                  \
        zend_register_internal_class_ex(&ce, spl_ce_InvalidArgumentException,  \
                                        NULL TSRMLS_CC);                       \
}
#endif

REGISTER_EXN(read,        bin_exn_read,        "bin_prot\\ReadError");
REGISTER_EXN(rpc,         bin_exn_rpc,         "bin_prot\\RPCError");
REGISTER_EXN(invalid_arg, bin_exn_invalid_arg, "bin_prot\\InvalidArg");
REGISTER_EXN(sum_tag,     bin_exn_sum_tag,     "bin_prot\\SumTag");
REGISTER_EXN(variant,     bin_exn_variant,     "bin_prot\\NoVariantMatch");

PHP_MINIT_FUNCTION(binprot)
{
    register_exn_read();
    register_exn_rpc();
    register_exn_invalid_arg();
    register_exn_sum_tag();
    register_exn_variant();

    le_rpc = zend_register_list_destructors_ex(NULL, rpc_resource_dtor,
                                               PHP_BIN_RPC, module_number);
    le_conn = zend_register_list_destructors_ex(NULL, conn_resource_dtor,
                                                PHP_BIN_CONN, module_number);

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
