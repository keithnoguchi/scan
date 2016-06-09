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

static inline void debug(const char *const fmt, ...)
{
	va_list ap;

	printf("[debug] ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static inline void dump(const unsigned char *const data_buffer,
		const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;

	for (i = 0; i < length; ++i) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);
		if (((i % 16) == 15) || (i == length - 1)) {
			/* Taking care of the last line case */
			for (j = 0; j < 15 - (i % 16); ++j)
				printf("   ");

			/* Separator between binary and the ASCII result */
			printf("| ");

			/* Print out the ASCII string. */
			for (j = (i - (i % 16)); j <= i; ++j) {
				byte = data_buffer[j];
				if (byte > 31 && byte < 127)
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}

#endif /* !_UTILS_H */
