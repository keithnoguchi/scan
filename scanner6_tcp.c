#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"

static const size_t tcphdrlen = 20;

/* Pseudo IP + TCP header for checksum calculation. */
struct cdata {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u_int32_t length;
	u_int8_t buf[3];
	u_int8_t nexthdr;
	struct tcphdr tcp;
};

static unsigned short tcp_checksum(struct scanner *sc, struct tcphdr *tcp)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	cdata->tcp = *tcp;
	return checksum((uint16_t *) cdata, sizeof(struct cdata));
}

static int reader(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct sockaddr_in6 addr;
	struct msghdr msg;
	struct iovec iov;
	unsigned short port;
	struct tcphdr *tcp;
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

	/* Ignore packet less than 20(TCP header size) bytes. */
	if (ret < tcphdrlen)
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
	tcp = (struct tcphdr *) sc->ibuf;
	port = ntohs(tcp->source);
	debug("Recv from %s:%d\n", sc->addr, port);

	dump(sc->ibuf, ret);
	sc->icounter++;

	/* We only care about packet with SA flag on. */
	if (tcp->syn == 0 || tcp->ack == 0) {
		debug("Drop packet w/o SYN/ACK from host(%s:%d)\n",
				sc->addr, port);
		return -1;
	}

	info("Port %d is open on %s\n", port, sc->addr);

	return port;
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct tcphdr *tcp;
	int ret;

	/* TCP header. */
	tcp = (struct tcphdr *) sc->obuf;
	tcp->source = htons(1024);
	tcp->dest = htons(sc->next_port);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->res1 = 0;
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->rst = tcp->psh = tcp->ack = tcp->urg = 0;
	tcp->res2 = 0;
	tcp->window = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;
	tcp->check = tcp_checksum(sc, tcp);

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

int scanner6_tcp_init(struct scanner *sc)
{
	struct cdata *cdata = (struct cdata *) sc->cbuf;
	struct sockaddr_in6 *sin;

	/* TCPv6 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* We only send TCP header portion. */
	sc->olen = sizeof(struct tcphdr);

	/* Prepare the checksum buffer. */
	sin = (struct sockaddr_in6 *) &sc->src;
	cdata->saddr = sin->sin6_addr;
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	cdata->daddr = sin->sin6_addr;
	cdata->length = htonl(tcphdrlen);
	cdata->buf[0] = cdata->buf[1] = cdata->buf[2] = 0;
	cdata->nexthdr = sc->dst->ai_protocol;

	return 0;
}
