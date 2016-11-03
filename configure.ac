AC_PREREQ([2.63])
AC_INIT([kexkill], [0.20161003], [des@des.no],
    [kexkill], [https://www.github.com/dag-erling/kexkill])
AC_CONFIG_SRCDIR([src/kexkill.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_CONFIG_HEADER(config.h)

# C compiler and features
AC_LANG(C)
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP
AC_GNU_SOURCE
AC_C_CONST

# other programs
AC_PROG_INSTALL

# options
AC_ARG_ENABLE([developer-warnings],
    AS_HELP_STRING([--enable-developer-warnings], [enable strict warnings (default is NO)]),
    [CFLAGS="${CFLAGS} -Wall -Wextra -Wcast-qual -Wshadow"])
AC_ARG_ENABLE([debugging-symbols],
    AS_HELP_STRING([--enable-debugging-symbols], [enable debugging symbols (default is NO)]),
    [CFLAGS="${CFLAGS} -O0 -g -fno-inline"])
AC_ARG_ENABLE([werror],
    AS_HELP_STRING([--enable-werror], [use -Werror (default is NO)]),
    [CFLAGS="${CFLAGS} -Werror"])

# output
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
