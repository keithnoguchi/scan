#ifndef _SCANNER_H
#define _SCANNER_H

#include <sys/types.h>
#include <sys/epoll.h>
#include <netdb.h>

struct scanner {
	/* Event manager. */
	struct epoll_event ev;
	int eventfd;

	/* Raw socket for the data packets. */
	int rawfd;

	/* Read/write buffers. */
	char ibuf[BUFSIZ];
	char obuf[BUFSIZ];
	size_t olen;

	/* Source and destination addresses. */
	struct addrinfo hints;
	struct sockaddr_storage src;
	struct addrinfo *dst;

	/* Scanning port related info. */
	int next_port;
	int start_port;
	int end_port;

	/* TCP header checksum buffer. */
	char cbuf[BUFSIZ];

	/* Reader and writer of the data packages. */
	int (*reader)(struct scanner *sc);
	int (*writer)(struct scanner *sc);
};

static inline void scanner_reader(struct scanner *sc)
{
	if (sc->reader)
		(*sc->reader)(sc);
}

static inline void scanner_writer(struct scanner *sc)
{
	if (sc->writer)
		(*sc->writer)(sc);
}

#endif /* _SCANNER_H */
