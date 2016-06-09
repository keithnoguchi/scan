#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "utils.h"
#include "scanner.h"
#include "scanner4_tcp.h"

/* Command line flags/arguments. */
bool debug_flag = false;
bool packet_dump_flag = false;
time_t duration_sec = 10;

/* Epoll timeout millisecond. */
static int epoll_timeout_millisec = 100;

static int srcaddr(struct scanner *sc, const char *ifname)
{
	struct ifaddrs *addrs, *ifa;
	int ret;

	ret = getifaddrs(&addrs);
	if (ret != 0)
		return ret;

	for (ifa = addrs; ifa != NULL; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == sc->dst->ai_family)
			if (ifname == NULL || !strcmp(ifa->ifa_name, ifname))
				if (ifa->ifa_flags & IFF_UP) {
					if (ifname == NULL
						&& (ifa->ifa_flags
							& IFF_LOOPBACK))
						continue;
					if (ifa->ifa_addr)
						memcpy(&sc->src,
							ifa->ifa_addr,
							sc->dst->ai_addrlen);
				}

	freeifaddrs(addrs);

	return ret;
}

static inline void scanner_reader(struct scanner *sc)
{
	if (sc->reader)
		while ((*sc->reader)(sc) != -1)
			; /* read as much as we can. */
}

static inline void scanner_writer(struct scanner *sc)
{
	if (sc->writer)
		if ((*sc->writer)(sc) < 0)
			return;

	if (++sc->next_port > sc->end_port) {
		/* Disable writer event. */
		epoll_ctl(sc->eventfd, EPOLL_CTL_DEL, sc->rawfd, NULL);
		sc->ev.events = EPOLLIN;
		sc->ev.data.fd = sc->rawfd;
		sc->ev.data.ptr = (void *)sc;
		epoll_ctl(sc->eventfd, EPOLL_CTL_MOD, sc->rawfd, &sc->ev);
		debug("Complete the probe transmission\n");
	}
}

int scanner_wait(struct scanner *sc)
{
	time_t now;
	int nfds;

	/* We've complete the scanning. */
	now = time(NULL);
	if (now - sc->start_time > duration_sec)
		return 0;

	/* Wait for the event, or timeout after epoll_timeout milliseconds. */
	nfds = epoll_wait(sc->eventfd, &sc->ev, 1, epoll_timeout_millisec);
	if (nfds == -1)
		fatal("epoll_wait(2)");

	return 1;
}

void scanner_exec(struct scanner *sc)
{
	if (sc->ev.events & EPOLLIN)
		scanner_reader(sc);
	if (sc->ev.events & EPOLLOUT)
		scanner_writer(sc);
	debug("tx: %d, rx: %d\n", sc->ocounter, sc->icounter);
}

void scanner_init(struct scanner *sc, const char *name, int family,
		int proto, const unsigned short start_port,
		const unsigned short end_port, const char *ifname)
{
	int ret, flags;

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

	/* Make socket non-blocking. */
	flags = fcntl(sc->rawfd, F_GETFL, 0);
	if (flags == -1)
		fatal("fcntl(F_GETFL)");
	ret = fcntl(sc->rawfd, F_SETFL, flags|O_NONBLOCK);
	if (ret == -1)
		fatal("fcntl(F_SETFL, O_NONBLOCK)");

	/* Source and destination addresses.  */
	memset(&sc->hints, 0, sizeof(sc->hints));
	sc->hints.ai_family = family;
	sc->hints.ai_socktype = SOCK_RAW;
	sc->hints.ai_protocol = proto;
	sc->hints.ai_addr = NULL;
	sc->hints.ai_next = NULL;
	ret = getaddrinfo(name, NULL, &sc->hints, &sc->dst);
	if (ret != 0)
		fatal("getaddrinfo(3)");
	ret = srcaddr(sc, ifname);
	if (ret != 0)
		fatal("getifaddrs(3)");

	/* Register it to the event manager. */
	sc->ev.events = EPOLLIN|EPOLLOUT;
	sc->ev.data.fd = sc->rawfd;
	sc->ev.data.ptr = (void *)sc;
	ret = epoll_ctl(sc->eventfd, EPOLL_CTL_ADD, sc->rawfd, &sc->ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");

	/* Member variable initialization. */
	sc->icounter = sc->ocounter = 0;
	sc->start_port = start_port;
	sc->end_port = end_port;
	sc->next_port = sc->start_port;

	/* Record the start time. */
	sc->start_time = time(NULL);

	switch (family) {
	case PF_INET:
		if (proto == IPPROTO_TCP)
			scanner_tcp4_init(sc);
		else
			fatal("TCP is the only supported protocol in IPv4\n");
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
	if (sc->dst != NULL) {
		freeaddrinfo(sc->dst);
		sc->dst = NULL;
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
