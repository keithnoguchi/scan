#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libnet.h>
#include <netdb.h>

#include "utils.h"

struct scanner {
	/* Event manager. */
	struct epoll_event ev;
	int eventfd;

	/* Raw socket for data packets. */
	int rawfd;

	/* Reader/writer buffers. */
	char buf[BUFSIZ];

	/* Destination address info. */
	struct addrinfo hints;
	struct addrinfo *addr;

	/* Scanning port info. */
	int next_port;
	int start_port;
	int end_port;

	/* Libnet handler for packat encoding/decoding. */
	libnet_ptag_t tcp, ip;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet;

	/* Reader and writer of the raw socket. */
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

int scanner_wait(struct scanner *sc)
{
	int nfds;

	nfds = epoll_wait(sc->eventfd, &sc->ev, 1, -1);
	if (nfds == -1)
		fatal("epoll_wait(2)");

	return 1;
}

void scanner_exec(struct scanner *sc)
{
	struct scanner *scp = (struct scanner *) sc->ev.data.ptr;

	if (sc->ev.events & EPOLLIN)
		scanner_reader(scp);
	if (sc->ev.events & EPOLLOUT)
		scanner_writer(scp);
}

static int reader(struct scanner *sc)
{
	int ret;

	ret = recv(sc->rawfd, sc->buf, sizeof(sc->buf), 0);
	if (ret < 0)
		fatal("recv(3)");

	dump(sc->buf, ret);

	return ret;
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sc->addr->ai_addr;
	unsigned char *buf;
	size_t len;
	int ret;

	printf("Here you go!\n\n\n");

	/* TCP header. */
	libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),           /* sp */
			sc->next_port,                             /* dp */
			libnet_get_prand(LIBNET_PRu32),            /* seq */
			libnet_get_prand(LIBNET_PRu32),            /* ack */
			TH_SYN,                                    /* ctrl */
			libnet_get_prand(LIBNET_PRu16),            /* win */
			0,                                         /* sum */
			0,                                         /* urg */
			LIBNET_TCP_H,                              /* len */
			NULL,                                      /* data */
			0,                                         /* dlen */
			sc->libnet,
			sc->tcp);

	/* IP header. */
	libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,            /* len */
			IPTOS_LOWDELAY,                            /* tos */
			libnet_get_prand(LIBNET_PRu16),            /* id */
			0,                                         /* frag */
			libnet_get_prand(LIBNET_PR8),              /* ttl */
			IPPROTO_TCP,                               /* proto */
			0,                                         /* sum */
			libnet_get_prand(LIBNET_PRu32),            /* sa */
			sin->sin_addr.s_addr,                      /* da */
			libnet_getpbuf(sc->libnet, sc->tcp),       /* data */
			libnet_getpbuf_size(sc->libnet, sc->tcp),  /* dlen */
			sc->libnet,
			sc->ip);

	buf = libnet_getpbuf(sc->libnet, sc->ip);
	len = libnet_getpbuf_size(sc->libnet, sc->ip);
	dump(buf, len);

	ret = send(sc->rawfd, buf, len, 0);
	if (ret != len)
		fatal("send()");

	if (++sc->next_port > sc->end_port) {
		/* Disable writer event. */
		sc->ev.events = EPOLLIN;
		epoll_ctl(sc->eventfd, EPOLL_CTL_MOD, sc->rawfd, &sc->ev);
		printf("done with sending\n");
	}
	return 0;
}

void scanner_tcp4_init(struct scanner *sc)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sc->addr->ai_addr;

	/* Initialize libnet random number generator. */
	sc->libnet = libnet_init(LIBNET_RAW4, NULL, sc->errbuf);
	if (sc->libnet == NULL)
		fatal("libnet_init(3)");

	/* Random number generator. */
	libnet_seed_prand(sc->libnet);

	/* TCP header. */
	sc->tcp = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), /* sp */
			sc->next_port,                             /* dp */
			libnet_get_prand(LIBNET_PRu32),            /* seq */
			libnet_get_prand(LIBNET_PRu32),            /* ack */
			TH_SYN,                                    /* ctrl */
			libnet_get_prand(LIBNET_PRu16),            /* win */
			0,                                         /* sum */
			0,                                         /* urg */
			LIBNET_TCP_H,                              /* len */
			NULL,                                      /* data */
			0,                                         /* dlen */
			sc->libnet,
			0);

	/* IP header. */
	sc->ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,   /* len */
			IPTOS_LOWDELAY,                            /* tos */
			libnet_get_prand(LIBNET_PRu16),            /* id */
			0,                                         /* frag */
			libnet_get_prand(LIBNET_PR8),              /* ttl */
			IPPROTO_TCP,                               /* proto */
			0,                                         /* sum */
			libnet_get_prand(LIBNET_PRu32),            /* sa */
			sin->sin_addr.s_addr,                      /* da */
			libnet_getpbuf(sc->libnet, sc->tcp),       /* data */
			libnet_getpbuf_size(sc->libnet, sc->tcp),  /* dlen */
			sc->libnet,
			0);

	sc->reader = reader;
	sc->writer = writer;
}

void scanner_init(struct scanner *sc, const char *name, int family,
		int proto, const int start_port, const int end_port)
{
	int ret;

	memset(sc, 0, sizeof(struct scanner));
	sc->eventfd = sc->rawfd = -1;

	/* Create event manager. */
	sc->eventfd = epoll_create1(0);
	if (sc->eventfd == -1)
		fatal("epoll_create1(2)");

	/* Create a raw socket. */
	sc->rawfd = socket(family, SOCK_RAW, proto);
	if (sc->rawfd == -1)
		fatal("socket(2)");

	/* Address info for the host. */
	memset(&sc->hints, 0, sizeof(sc->hints));
	sc->hints.ai_family = family;
	sc->hints.ai_socktype = SOCK_RAW;
	sc->hints.ai_protocol = proto;
	sc->hints.ai_addr = NULL;
	sc->hints.ai_next = NULL;
	ret = getaddrinfo(name, NULL, &sc->hints, &sc->addr);
	if (ret != 0)
		fatal("getaddrinfo(3)");

	/* Register it to the event manager. */
	sc->ev.events = EPOLLIN|EPOLLOUT;
	sc->ev.data.fd = sc->rawfd;
	sc->ev.data.ptr = (void *)sc;
	ret = epoll_ctl(sc->eventfd, EPOLL_CTL_ADD, sc->rawfd, &sc->ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");

	/* Member variable initialization. */
	sc->start_port = start_port;
	sc->end_port = end_port;
	sc->next_port = sc->start_port;

	switch (family) {
	case PF_INET:
		if (proto == IPPROTO_TCP)
			scanner_tcp4_init(sc);
		else
			fatal("TCPv4 is only supported\n");
		break;
	case PF_INET6:
		fatal("IPv6 is not supported\n");
		break;
	default:
		fatal("Unsupported protocol family\n");
		break;
	 }
}

void scanner_term(struct scanner *sc)
{
	if (sc->libnet != NULL) {
		libnet_clear_packet(sc->libnet);
		libnet_destroy(sc->libnet);
		sc->libnet = NULL;
	}

	if (sc->addr != NULL) {
		freeaddrinfo(sc->addr);
		sc->addr = NULL;
	}

	if (sc->rawfd != -1) {
		if (sc->eventfd != -1)
			epoll_ctl(sc->eventfd, EPOLL_CTL_DEL,
					sc->rawfd, NULL);
		close(sc->rawfd);
	}
	if (sc->eventfd != -1) {
		close(sc->eventfd);
	}
	memset(sc, 0, sizeof(struct scanner));
	sc->eventfd = sc->rawfd = -1;
}

int main(int argc, char *argv[])
{
	const int start_port = 0;
	const int end_port = 65535;
	struct scanner sc;

	if (argc < 2) {
		printf("Usage: %s <hostname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Initialize the scanner with the hostname, address family,
	 * and the protocol. */
	scanner_init(&sc, argv[1], PF_INET, IPPROTO_TCP, start_port,
			end_port);

	/* Light the fire! */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Done with the scanning. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}
