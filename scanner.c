#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "utils.h"
#include "scanner.h"
#include "scanner4_tcp.h"

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

void scanner_init(struct scanner *sc, const char *name, int family,
		int proto, const int start_port, const int end_port,
		const char *ifname)
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
	sc->start_port = start_port;
	sc->end_port = end_port;
	sc->next_port = sc->start_port;

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
