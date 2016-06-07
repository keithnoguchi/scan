#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "utils.h"

const int scanner_default_start_port = 0;
const int scanner_default_end_port = 65535;
char *const scanner_default_ifname = NULL;

struct scanner {
	/* Event manager. */
	struct epoll_event ev;
	int eventfd;

	/* Raw socket for the data packets. */
	int rawfd;

	/* Read/write buffers. */
	char ibuf[BUFSIZ];
	char obuf[BUFSIZ];

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

	ret = recv(sc->rawfd, sc->ibuf, sizeof(sc->ibuf), 0);
	if (ret < 0)
		fatal("recv(3)");

	printf("->\n");
	dump(sc->ibuf, ret);

	return ret;
}

static unsigned short checksum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

static unsigned short tcp4_checksum(struct scanner *sc, struct iphdr *ip,
		struct tcphdr *tcp)
{
	struct iptmp {
		u_int32_t saddr;
		u_int32_t daddr;
		u_int8_t buf;
		u_int8_t protocol;
		u_int16_t length;
		struct tcphdr tcp;
	} *tmp = (struct iptmp *) sc->cbuf;
	tmp->tcp = *tcp;

	return checksum((uint16_t *) sc->cbuf, sizeof(*tmp));
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in *sin;
	size_t len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct tcphdr *tcp;
	struct iphdr *ip;
	int ret;

	printf("<-\n");

	/* IP header. */
	ip = (struct iphdr *) sc->obuf;
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = 0;
	ip->id = htonl(54321);
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	sin = (struct sockaddr_in *) &sc->src;
	ip->saddr = sin->sin_addr.s_addr;
	sin = (struct sockaddr_in *) sc->dst->ai_addr;
	ip->daddr = sin->sin_addr.s_addr;

	/* TCP header. */
	tcp = (struct tcphdr *)(sc->obuf + 20);
	tcp->th_sport = 0;
	tcp->th_dport = htons(sc->next_port);
	tcp->th_seq = 0;
	tcp->th_ack = 0;
	tcp->th_x2 = 0;
	tcp->th_off = 5;
	tcp->th_flags = TH_SYN;
	tcp->th_win = 0;
	tcp->th_sum = 0;
	tcp->th_urp = 0;
	tcp->th_sum = tcp4_checksum(sc, ip, tcp);

	dump(sc->obuf, len);

	ret = sendto(sc->rawfd, sc->obuf, len, 0, sc->dst->ai_addr,
			sc->dst->ai_addrlen);
	if (ret != len)
		fatal("sendto()");

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
	struct iphdr *ip = (struct iphdr *) sc->obuf;
	struct sockaddr_in *sin;
	int on = 1;
	int ret;

	ret = setsockopt(sc->rawfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (ret != 0)
		fatal("setsockopt(3)");

	/* TCPv4 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* Prepare the IP header. */
	ip = (struct iphdr *) sc->obuf;
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = 0;
	ip->id = htonl(54321);
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	sin = (struct sockaddr_in *) &sc->src;
	ip->saddr = sin->sin_addr.s_addr;
	sin = (struct sockaddr_in *) sc->dst->ai_addr;
	ip->daddr = sin->sin_addr.s_addr;

	/* Prepare the checksum buffer. */
	struct iptmp {
		u_int32_t saddr;
		u_int32_t daddr;
		u_int8_t buf;
		u_int8_t protocol;
		u_int16_t length;
		struct tcphdr tcp;
	} *tmp = (struct iptmp *) sc->cbuf;
	tmp->saddr = ip->saddr;
	tmp->daddr = ip->daddr;
	tmp->buf = 0;
	tmp->protocol = ip->protocol;
	tmp->length = htons(20);
}

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
				if (ifa->ifa_flags & IFF_UP
					&& !(ifa->ifa_flags & IFF_LOOPBACK))
					if (ifa->ifa_addr)
						memcpy(&sc->src,
							ifa->ifa_addr,
							sc->dst->ai_addrlen);

	freeifaddrs(addrs);

	return ret;
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

int main(int argc, char *argv[])
{
	int start_port = scanner_default_start_port;
	int end_port = scanner_default_end_port;
	char *ifname = scanner_default_ifname;
	struct scanner sc;
	char *dstname;

	if (argc < 2) {
		printf("Usage: %s <hostname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	dstname = argv[1];
	if (argc >= 3) {
		start_port = end_port = atoi(argv[2]);
	}
	if (argc >= 4)
		ifname = argv[3];

	/* Initialize the scanner with the hostname, address family,
	 * and the protocol. */
	scanner_init(&sc, dstname, PF_INET, IPPROTO_TCP, start_port,
			end_port, ifname);

	/* Light the fire! */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Done with the scanning. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}
