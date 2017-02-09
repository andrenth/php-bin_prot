dnl $Id$
dnl config.m4 for extension bin_prot

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(bin_prot,      whether to enable bin_prot support,
[  --with-bin_prot[=DIR]    Enable bin_prot support.], yes)


if test "$PHP_BIN_PROT" != "no"; then

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  if test "x$PKG_CONFIG" = "xno"; then
    AC_MSG_RESULT([pkg-config not found])
    AC_MSG_ERROR([Please reinstall the pkg-config distribution])
  fi

  ORIG_PKG_CONFIG_PATH=$PKG_CONFIG_PATH

  PHP_BIN_PROT_EXPLICIT_PKG_CONFIG_PATH=""

  AC_MSG_CHECKING(libbin_prot installation)
  if test "x$PHP_BIN_PROT" = "xyes"; then
    if test "x${PKG_CONFIG_PATH}" = "x"; then
      export PKG_CONFIG_PATH="/usr/local/${PHP_LIBDIR}/pkgconfig:/usr/${PHP_LIBDIR}/pkgconfig:/opt/${PHP_LIBDIR}/pkgconfig:/opt/local/${PHP_LIBDIR}/pkgconfig"
    else
      export PKG_CONFIG_PATH="${PHP_BIN_PROT}/${PHP_LIBDIR}/pkgconfig"
      export PHP_BIN_PROT_EXPLICIT_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
    fi
  fi

  if $PKG_CONFIG --exists libbin_prot; then
    PHP_BIN_PROT_VERSION=`$PKG_CONFIG libbin_prot --modversion`
    PHP_BIN_PROT_PREFIX=`$PKG_CONFIG libbin_prot --variable=prefix`

    AC_MSG_RESULT([found version $PHP_BIN_PROT_VERSION, under $PHP_BIN_PROT_PREFIX])
    PHP_BIN_PROT_LIBS=`$PKG_CONFIG libbin_prot --libs`
    PHP_BIN_PROT_CFLAGS=`$PKG_CONFIG libbin_prot --cflags`

    PHP_EVAL_LIBLINE($PHP_BIN_PROT_LIBS, BIN_PROT_SHARED_LIBADD)
    PHP_EVAL_INCLINE($PHP_BIN_PROT_CFLAGS)
  else
    AC_MSG_ERROR(Unable to find libbin_prot installation)
  fi

  PHP_SUBST(BIN_PROT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(bin_prot, bin_prot.c, $ext_shared)
  PKG_CONFIG_PATH="$ORIG_PKG_CONFIG_PATH"
fi
