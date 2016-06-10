#include <errno.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#define __USE_KERNEL_IPV6_DEFS
#include <netinet/in.h>
#undef __USE_KERNEL_IPV6_DEFS
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* !INET6_ADDRSTRLEN */

static const size_t iphdrlen = 40;
static const size_t tcphdrlen = 20;

static int reader(struct scanner *sc)
{
	char src[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin;
	unsigned short port;
	struct tcphdr *tcp;
	struct ipv6hdr *ip;
	int ret;

	/* Drop the packet which is not from the destination. */
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	ip = (struct ipv6hdr *) sc->ibuf;
	if (!memcmp(&ip->saddr, &sin->sin6_addr, sizeof(struct in6_addr))) {
		debug("Drop packet from non-target host(%s)\n",
			inet_ntop(AF_INET6, &ip->saddr, src, sizeof(src)));
		return -1;
	}

	inet_ntop(AF_INET6, &ip->saddr, src, sizeof(src));
	tcp = (struct tcphdr *) (ip + 1);
	port = ntohs(tcp->source);
	debug("Recv from %s:%d\n", src, port);
	dump(sc->ibuf, ret);
	sc->icounter++;

	/* Ignore packet less than 40(IP + TCP header size) bytes. */
	if (ret < iphdrlen + tcphdrlen)
		return -1;

	/* We only care about packet with SA flag on. */
	if (tcp->syn == 0 || tcp->ack == 0) {
		debug("Drop packet w/o SYN/ACK from host(%s:%d)\n", src, port);
		return -1;
	}

	info("Port %d is open on %s\n", port, src);

	return port;
}

static unsigned short tcp_checksum(struct scanner *sc, struct tcphdr *tcp)
{
	struct cdata {
		struct in6_addr saddr;
		struct in6_addr daddr;
		u_int16_t length;
		u_int8_t buf[3];
		u_int8_t nexthdr;
		struct tcphdr tcp;
	} *cdata = (struct cdata *) sc->cbuf;
	cdata->tcp = *tcp;

	return checksum((uint16_t *) cdata, sizeof(struct cdata));
}

static int writer(struct scanner *sc)
{
	char dst[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin;
	struct tcphdr *tcp;
	struct ipv6hdr *ip;

	/* IP header. */
	ip = (struct ipv6hdr *) sc->obuf;

	/* TCP header. */
	tcp = (struct tcphdr *)(sc->obuf + tcphdrlen);
	tcp->source = htons(1024);
	tcp->dest = htons(sc->next_port);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->res1 = 0;
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->window = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;
	tcp->check = tcp_checksum(sc, tcp);

	inet_ntop(AF_INET6, &ip->daddr, dst, sizeof(dst));
	debug("Sent to %s:%d\n", dst, ntohs(tcp->dest));
	dump(sc->obuf, sc->olen);

	return 0;
}

void scanner_tcp6_init(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct ipv6hdr *ip;
	int on = 1;
	int ret;

	ret = setsockopt(sc->rawfd, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on));
	if (ret != 0)
		fatal("setsockopt(3)");

	/* TCPv6 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* Prepare the IP header. */
	ip = (struct ipv6hdr *) sc->obuf;
	ip->version = 6;
	ip->priority = 0;
	ip->payload_len = htons(tcphdrlen);
	ip->nexthdr = sc->dst->ai_protocol;
	ip->hop_limit = 255;
	sin = (struct sockaddr_in6 *) &sc->src;
	memcpy(&ip->saddr, &sin->sin6_addr, sizeof(struct in6_addr));
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	memcpy(&ip->daddr, &sin->sin6_addr, sizeof(struct in6_addr));

	/* We only send TCP/IP header portion. */
	sc->olen = sizeof(struct ipv6hdr) + sizeof(struct tcphdr);

	/* Prepare the checksum buffer. */
	struct cdata {
		struct in6_addr saddr;
		struct in6_addr daddr;
		u_int16_t length;
		u_int8_t buf[3];
		u_int8_t nexthdr;
		struct tcphdr tcp;
	} *cdata = (struct cdata *) sc->cbuf;
	memcpy(&cdata->saddr, &ip->saddr, sizeof(struct in6_addr));
	memcpy(&cdata->daddr, &ip->daddr, sizeof(struct in6_addr));
	cdata->buf[0] = cdata->buf[1] = cdata->buf[2] = 0;
	cdata->nexthdr = ip->nexthdr;
	cdata->length = htons(iphdrlen);
}
