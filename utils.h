#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

static inline void fatal(const char *const fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;

	if (errno != 0)
		strerror_r(errno, buf, sizeof(buf));
	fprintf(stderr, "[fatal] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (buf[0] != '\0')
		fprintf(stderr, ": %s", buf);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static inline void warn(const char *const fmt, ...)
{
	va_list ap;

	printf("[warn] ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static inline void info(const char *const fmt, ...)
{
	extern bool debug_flag, verbose_flag, packet_dump_flag;
	va_list ap;

	if (verbose_flag == false
		&& debug_flag == false
		&& packet_dump_flag == false)
		return;
	printf("[info] ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static inline void debug(const char *const fmt, ...)
{
	extern bool debug_flag;
	va_list ap;

	if (debug_flag == false)
		return;
	printf("[debug] ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static inline int output(const char *const fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);

	return ret;
}

static inline void dump(const unsigned char *const data_buffer,
		const unsigned int length)
{
	extern bool packet_dump_flag;
	unsigned char byte;
	unsigned int i, j;

	if (packet_dump_flag == false)
		return;

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
