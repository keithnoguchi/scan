#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([scan], [1.0], [keith.noguchi@gmail.com])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([tracker.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([CppUTest], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h \
		  fcntl.h \
		  netdb.h \
		  netinet/in.h \
		  stdint.h \
		  stdlib.h \
		  string.h \
		  sys/socket.h \
		  unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
