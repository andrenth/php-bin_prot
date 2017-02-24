#ifndef PHP_BINPROT_H
#define PHP_BINPROT_H

#define PHP_BINPROT_VERSION "0.0.1"

#define PHP_BIN_RPC  "bin_rpc"
#define PHP_BIN_CONN "bin_rpc_connection"

#define PHP_BIN_READ_NS  "bin_prot\\read"
#define PHP_BIN_WRITE_NS "bin_prot\\write"
#define PHP_BIN_SIZE_NS  "bin_prot\\size"
#define PHP_BIN_RPC_NS   "bin_prot\\rpc"

extern zend_module_entry binprot_module_entry;
#define phpext_binprot_ptr &binprot_module_entry

PHP_MINIT_FUNCTION(binprot);
PHP_MSHUTDOWN_FUNCTION(binprot);
PHP_MINFO_FUNCTION(binprot);

PHP_FUNCTION(bin_read_nat0);
PHP_FUNCTION(bin_read_int);
PHP_FUNCTION(bin_read_int32);
PHP_FUNCTION(bin_read_int64);
PHP_FUNCTION(bin_read_int_8bit);
PHP_FUNCTION(bin_read_int_16bit);
PHP_FUNCTION(bin_read_int_32bit);
PHP_FUNCTION(bin_read_int_64bit);
PHP_FUNCTION(bin_read_network16_int);
PHP_FUNCTION(bin_read_network32_int);
PHP_FUNCTION(bin_read_network64_int);
PHP_FUNCTION(bin_read_variant_int);
PHP_FUNCTION(bin_read_float);
PHP_FUNCTION(bin_read_string);
PHP_FUNCTION(bin_read_digest);
PHP_FUNCTION(bin_read_unit);
PHP_FUNCTION(bin_read_char);
PHP_FUNCTION(bin_read_option);
PHP_FUNCTION(bin_read_pair);
PHP_FUNCTION(bin_read_triple);
PHP_FUNCTION(bin_read_array);
PHP_FUNCTION(bin_read_list);
PHP_FUNCTION(bin_read_hashtbl);

PHP_FUNCTION(bin_write_char);
PHP_FUNCTION(bin_write_option);
PHP_FUNCTION(bin_write_nat0);
PHP_FUNCTION(bin_write_int);
PHP_FUNCTION(bin_write_int32);
PHP_FUNCTION(bin_write_int64);
PHP_FUNCTION(bin_write_int_8bit);
PHP_FUNCTION(bin_write_int_16bit);
PHP_FUNCTION(bin_write_int_32bit);
PHP_FUNCTION(bin_write_int_64bit);
PHP_FUNCTION(bin_write_network16_int);
PHP_FUNCTION(bin_write_network32_int);
PHP_FUNCTION(bin_write_network64_int);
PHP_FUNCTION(bin_write_variant_int);
PHP_FUNCTION(bin_write_float);
PHP_FUNCTION(bin_write_string);
PHP_FUNCTION(bin_write_digest);
PHP_FUNCTION(bin_write_array);
PHP_FUNCTION(bin_write_list);
PHP_FUNCTION(bin_write_hashtbl);
PHP_FUNCTION(bin_write_unit);
PHP_FUNCTION(bin_write_pair);
PHP_FUNCTION(bin_write_triple);

PHP_FUNCTION(bin_size_char);
PHP_FUNCTION(bin_size_option);
PHP_FUNCTION(bin_size_nat0);
PHP_FUNCTION(bin_size_int);
PHP_FUNCTION(bin_size_int32);
PHP_FUNCTION(bin_size_int64);
PHP_FUNCTION(bin_size_int_8bit);
PHP_FUNCTION(bin_size_int_16bit);
PHP_FUNCTION(bin_size_int_32bit);
PHP_FUNCTION(bin_size_int_64bit);
PHP_FUNCTION(bin_size_network16_int);
PHP_FUNCTION(bin_size_network32_int);
PHP_FUNCTION(bin_size_network64_int);
PHP_FUNCTION(bin_size_variant_int);
PHP_FUNCTION(bin_size_float);
PHP_FUNCTION(bin_size_string);
PHP_FUNCTION(bin_size_digest);
PHP_FUNCTION(bin_size_array);
PHP_FUNCTION(bin_size_list);
PHP_FUNCTION(bin_size_hashtbl);
PHP_FUNCTION(bin_size_unit);
PHP_FUNCTION(bin_size_pair);
PHP_FUNCTION(bin_size_triple);

PHP_FUNCTION(bin_rpc_client);
PHP_FUNCTION(bin_rpc_create);
PHP_FUNCTION(bin_rpc_dispatch);

#endif
