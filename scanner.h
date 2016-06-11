#ifndef _SCANNER_H
#define _SCANNER_H

#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

/* Command line options/arguments. */
extern bool debug_flag;
extern bool packet_dump_flag;
extern time_t duration_sec;

/* Scanner manager. */
struct scanner {
	/* Event manager. */
	struct epoll_event ev;
	int eventfd;

	/* Raw socket for the data packets. */
	int rawfd;

	/* Start time. */
	time_t start_time;

	/* Read/write buffers. */
	unsigned char ibuf[BUFSIZ];
	unsigned char obuf[BUFSIZ];
	size_t olen;

	/* Source and destination addresses. */
	struct sockaddr_storage src;
	struct addrinfo *dst;

	/* Address string buffer. */
	size_t addrstr_len;
	char *addr;

	/* Scanning port related info. */
	int next_port;
	int start_port;
	int end_port;

	/* Packet counters. */
	size_t icounter;
	size_t ocounter;

	/* TCP/UDP checksum buffer. */
	unsigned char cbuf[BUFSIZ];

	/* Address validator. */
	bool (*is_ll_addr)(struct scanner *sc, const struct sockaddr *sa);

	/* Reader and writer of the data packages. */
	int (*reader)(struct scanner *sc);
	int (*writer)(struct scanner *sc);
};

/* Inlines. */
static inline unsigned short checksum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

/* Prototypes. */
int scanner_wait(struct scanner *sc);
void scanner_exec(struct scanner *sc);
int scanner_init(struct scanner *sc, const char *name, int family,
		int proto, const unsigned short start_port,
		const unsigned short end_port, const char *ifname);
void scanner_term(struct scanner *sc);

#endif /* _SCANNER_H */
