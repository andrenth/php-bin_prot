#ifndef PHP_BINPROT_H
#define PHP_BINPROT_H

extern zend_module_entry binprot_module_entry;
#define phpext_binprot_ptr &binprot_module_entry

PHP_MINIT_FUNCTION(binprot);
PHP_MSHUTDOWN_FUNCTION(binprot);
PHP_MINFO_FUNCTION(binprot);

#endif
