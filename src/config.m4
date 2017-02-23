PHP_ARG_ENABLE(binprot, whether to enable bin_prot support,
[  --enable-binprot           Enable binprot support])

if test "$PHP_BINPROT" != "no"; then
  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  if test "x$PKG_CONFIG" = "xno"; then
    AC_MSG_RESULT([pkg-config not found])
    AC_MSG_ERROR([Please reinstall the pkg-config distribution])
  fi

  ORIG_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
  PHP_BINPROT_EXPLICIT_PKG_CONFIG_PATH=""

  AC_MSG_CHECKING(libbin_prot installation)
  if test "x$PHP_BINPROT" = "xyes"; then
    if test "x${PKG_CONFIG_PATH}" = "x"; then
      export PKG_CONFIG_PATH="/usr/local/${PHP_LIBDIR}/pkgconfig:/usr/${PHP_LIBDIR}/pkgconfig:/opt/${PHP_LIBDIR}/pkgconfig:/opt/local/${PHP_LIBDIR}/pkgconfig"
    else
      export PKG_CONFIG_PATH="${PHP_BINPROT}/${PHP_LIBDIR}/pkgconfig"
      export PHP_BINPROT_EXPLICIT_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
    fi
  fi

  if $PKG_CONFIG --exists libbin_prot; then
    PHP_BINPROT_VERSION=`$PKG_CONFIG libbin_prot --modversion`
    PHP_BINPROT_PREFIX=`$PKG_CONFIG libbin_prot --variable=prefix`

    AC_MSG_RESULT([found version $PHP_BINPROT_VERSION, under $PHP_BINPROT_PREFIX])
    PHP_BINPROT_LIBS=`$PKG_CONFIG libbin_prot --libs`
    PHP_BINPROT_CFLAGS=`$PKG_CONFIG libbin_prot --cflags`

    PHP_EVAL_LIBLINE($PHP_BINPROT_LIBS, BINPROT_SHARED_LIBADD)
    PHP_EVAL_INCLINE($PHP_BINPROT_CFLAGS)
  else
    AC_MSG_ERROR(Unable to find libbin_prot installation)
  fi

  PHP_SUBST(BINPROT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(binprot, \
    bin_prot_common.c        \
    bin_prot_read.c          \
    bin_prot_write.c         \
    bin_prot_size.c          \
    bin_prot_rpc.c           \
    php_bin_prot.c           \
  , $ext_shared)

  PHP_ADD_EXTENSION_DEP(binprot, spl)

  PKG_CONFIG_PATH="$ORIG_PKG_CONFIG_PATH"
fi
