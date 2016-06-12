#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"
#include "tracker.h"

static const size_t udphdrlen = 8;

/* Pseudo IP + UDP header for checksum calculation. */
struct cdata {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u_int32_t length;
	u_int8_t buf[3];
	u_int8_t nexthdr;
	struct udphdr udp;
};

static unsigned short udp_checksum(struct scanner *sc, struct udphdr *udp)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	cdata->udp = *udp;
	return checksum((uint16_t *) cdata, sizeof(struct cdata));
}

static int udp_reader(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct sockaddr_in6 addr;
	struct msghdr msg;
	struct iovec iov;
	unsigned short port;
	struct udphdr *udp;
	int ret;

	iov.iov_base = sc->ibuf;
	iov.iov_len = sizeof(sc->ibuf);
	msg.msg_name = (struct sockaddr *) &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret = recvmsg(sc->rawfd, &msg, 0);
	if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		fatal("recv(3)");
	}

	/* Ignore packet less than 8(UDP header) bytes. */
	if (ret < udphdrlen)
		return -1;

	/* Drop the packet which is not from the destination. */
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	if (!IN6_ARE_ADDR_EQUAL(&addr.sin6_addr, &sin->sin6_addr)) {
		debug("Drop packet from non-target host(%s)\n",
			inet_ntop(AF_INET6, &addr.sin6_addr, sc->addr,
				INET6_ADDRSTRLEN));
		return -1;
	}

	inet_ntop(AF_INET6, &addr.sin6_addr, sc->addr, INET6_ADDRSTRLEN);
	udp = (struct udphdr *) sc->ibuf;
	port = ntohs(udp->source);
	debug("Recv from %s:%d\n", sc->addr, port);
	dump(sc->ibuf, ret);
	sc->icounter++;

	/* Report the port is open! */
	tracker_set_open(&sc->tracker, port);

	return ret;
}

static int reader(struct scanner *sc)
{
	/* We need to figure out how to multiplex those two
	 * sockets through epoll in the future. */
	return udp_reader(sc);
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct udphdr *udp;
	int ret;

	/* UDP header. */
	udp = (struct udphdr *) sc->obuf;
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
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	inet_ntop(AF_INET6, &sin->sin6_addr, sc->addr, INET6_ADDRSTRLEN);

	return ret;
}

int scanner6_udp_init(struct scanner *sc)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	struct sockaddr_in6 *sin;

	/* TCPv6 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* We only send UDP header portion. */
	sc->olen = sizeof(struct udphdr);

	/* Prepare the checksum buffer. */
	sin = (struct sockaddr_in6 *) &sc->src;
	cdata->saddr = sin->sin6_addr;
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	cdata->daddr = sin->sin6_addr;
	cdata->length = htonl(udphdrlen);
	cdata->buf[0] = cdata->buf[1] = cdata->buf[2] = 0;
	cdata->nexthdr = sc->dst->ai_protocol;

	return 0;
}
