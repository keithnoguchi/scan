#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"

static const size_t iphdrlen = 20;
static const size_t icmphdrlen = 8;
static const size_t udphdrlen = 8;

/* Pseudo IP + TCP header for checksum calculation. */
struct cdata {
	u_int32_t saddr;
	u_int32_t daddr;
	u_int8_t buf;
	u_int8_t protocol;
	u_int16_t length;
	struct udphdr udp;
};

static unsigned short udp_checksum(struct scanner *sc, struct udphdr *udp)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	cdata->udp = *udp;
	return checksum((uint16_t *) cdata, sizeof(struct cdata));
}

static int icmp_reader(struct scanner *sc)
{
	struct sockaddr_in *sin;
	unsigned short port;
	struct udphdr *udp;
	struct icmphdr *icmp;
	struct iphdr *ip;
	int ret;

	ret = recv(sc->exceptfd, sc->ibuf, sizeof(sc->ibuf), 0);
	if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		fatal("recv(3)");
	}

	/* Ignore packet less than 56(IP + ICMP + IP + UDP header) bytes. */
	if (ret < iphdrlen + icmphdrlen + udphdrlen)
		return -1;

	/* Drop the packet which is not from the destination. */
	sin = (struct sockaddr_in *) sc->dst->ai_addr;
	ip = (struct iphdr *) sc->ibuf;
	if (ip->saddr != sin->sin_addr.s_addr) {
		debug("Drop packet from non-target host(%s)\n",
			inet_ntop(AF_INET, &ip->saddr, sc->addr,
				INET_ADDRSTRLEN));
		return -1;
	}

	inet_ntop(AF_INET, &ip->saddr, sc->addr, INET_ADDRSTRLEN);
	icmp = (struct icmphdr *) (ip + 1);
	ip = (struct iphdr *) (icmp + 1);
	udp = (struct udphdr *) (ip + 1);
	port = ntohs(udp->dest);
	debug("Recv from %s:%d\n", sc->addr, port);
	dump(sc->ibuf, ret);
	sc->icounter++;

	/* Report the port is closed. */
	tracker_set_closed(&sc->tracker, port);

	return ret;
}

static int reader(struct scanner *sc)
{
	struct sockaddr_in *sin;
	unsigned short port;
	struct udphdr *udp;
	struct iphdr *ip;
	int ret;

	ret = recv(sc->rawfd, sc->ibuf, sizeof(sc->ibuf), 0);
	if (ret < 0) {
		if (errno == EAGAIN)
			return icmp_reader(sc);
		fatal("recv(3)");
	}

	/* Ignore packet less than 28(IP + UDP header) bytes. */
	if (ret < iphdrlen + udphdrlen)
		return -1;

	/* Drop the packet which is not from the destination. */
	sin = (struct sockaddr_in *) sc->dst->ai_addr;
	ip = (struct iphdr *) sc->ibuf;
	if (ip->saddr != sin->sin_addr.s_addr) {
		debug("Drop packet from non-target host(%s)\n",
			inet_ntop(AF_INET, &ip->saddr, sc->addr,
				INET_ADDRSTRLEN));
		return -1;
	}

	inet_ntop(AF_INET, &ip->saddr, sc->addr, INET_ADDRSTRLEN);
	udp = (struct udphdr *) (ip + 1);
	port = ntohs(udp->source);
	debug("Recv from %s:%d\n", sc->addr, port);
	dump(sc->ibuf, ret);
	sc->icounter++;

	return port;
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in *sin;
	struct udphdr *udp;
	struct iphdr *ip;
	int ret;

	/* IP header. */
	ip = (struct iphdr *) sc->obuf;
	ip->id = htonl(54321); /* randomize. */

	/* UDP header. */
	udp = (struct udphdr *)(sc->obuf + iphdrlen);
	udp->source = htons(1024);
	udp->dest = htons(sc->tracker.next);
	udp->len = htons(udphdrlen);
	udp->check = 0;
	udp->check = udp_checksum(sc, udp);

	ret = sendto(sc->rawfd, sc->obuf, sc->olen, 0, sc->dst->ai_addr,
			sc->dst->ai_addrlen);
	if (ret != sc->olen) {
		if (ret < 0)
			warn("sendto() error\n");
		else
			info("sendto() can't send full data\n");
		return -1;
	}

	/* Store the destination address string for debugging purpose. */
	inet_ntop(AF_INET, &ip->daddr, sc->addr, INET_ADDRSTRLEN);

	return ret;
}

int scanner4_udp_init(struct scanner *sc)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	struct iphdr *ip = (struct iphdr *) sc->obuf;
	int ret, flags;

	/* Create an exception socket for ICMP packet handling. */
	sc->exceptfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sc->exceptfd == -1)
		fatal("socket(IPPROTO_ICMP");

	/* Register it to the event manager. */
	sc->ev.events = EPOLLIN;
	sc->ev.data.fd = sc->exceptfd;
	sc->ev.data.ptr = (void *)sc;
	ret = epoll_ctl(sc->eventfd, EPOLL_CTL_ADD, sc->exceptfd, &sc->ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");

	/* Make socket non-blocking. */
	flags = fcntl(sc->exceptfd, F_GETFL, 0);
	if (flags == -1)
		fatal("fcntl(F_GETFL)");
	ret = fcntl(sc->exceptfd, F_SETFL, flags|O_NONBLOCK);
	if (ret == -1)
		fatal("fcntl(F_SETFL, O_NONBLOCK)");

	/* Change the default port status to all open. */
	tracker_open_all(&sc->tracker);

	/* TCPv4 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* We send both IP and TCP header portion. */
	sc->olen = sizeof(struct iphdr) + sizeof(struct udphdr);

	/* Prepare the checksum buffer. */
	cdata->saddr = ip->saddr;
	cdata->daddr = ip->daddr;
	cdata->buf = 0;
	cdata->protocol = sc->dst->ai_protocol;
	cdata->length = htons(udphdrlen);

	return 0;
}
