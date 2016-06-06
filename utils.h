#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static inline void fatal(const char *const fmt, ...)
{
	char buf[BUFSIZ];
	va_list ap;

	strerror_r(errno, buf, sizeof(buf));
	fprintf(stderr, "[fatal] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", buf);

	exit(EXIT_FAILURE);
}

#endif /* !_UTILS_H */
