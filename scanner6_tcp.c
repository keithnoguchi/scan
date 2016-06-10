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

static const size_t iphdrlen = 40;
static const size_t tcphdrlen = 20;

static int reader(struct scanner *sc)
{
	char src[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin;
	unsigned short port;
	struct tcphdr *tcp;
	struct ip6_hdr *ip;
	int ret;

	/* Drop the packet which is not from the destination. */
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	ip = (struct ip6_hdr *) sc->ibuf;
	if (!memcmp(&ip->ip6_src, &sin->sin6_addr, sizeof(struct in6_addr))) {
		debug("Drop packet from non-target host(%s)\n",
			inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src)));
		return -1;
	}

	inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src));
	tcp = (struct tcphdr *) (ip + 1);
	port = ntohs(tcp->source);
	debug("Recv from %s:%d\n", src, port);
	dump(sc->ibuf, ret);
	sc->icounter++;

	/* Ignore packet less than 60(IP + TCP header size) bytes. */
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
	struct ip6_hdr *ip;

	/* IP header. */
	ip = (struct ip6_hdr *) sc->obuf;

	/* TCP header. */
	tcp = (struct tcphdr *)(sc->obuf + tcphdrlen);
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

	inet_ntop(AF_INET6, &ip->ip6_dst, dst, sizeof(dst));
	debug("Sent to %s:%d\n", dst, ntohs(tcp->dest));
	dump(sc->obuf, sc->olen);

	return 0;
}

void scanner_tcp6_init(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct ip6_hdr *ip;
	int on = 1;
	int ret;

	ret = setsockopt(sc->rawfd, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on));
	if (ret != 0)
		fatal("setsockopt(3)");

	/* TCPv6 specific reader/writer. */
	sc->reader = reader;
	sc->writer = writer;

	/* Prepare the IP header. */
	ip = (struct ip6_hdr *) sc->obuf;
	ip->ip6_vfc = 6 << 4;
	ip->ip6_plen = htons(tcphdrlen);
	ip->ip6_nxt = sc->dst->ai_protocol;
	ip->ip6_hlim = 255;
	sin = (struct sockaddr_in6 *) &sc->src;
	memcpy(&ip->ip6_src, &sin->sin6_addr, sizeof(struct in6_addr));
	sin = (struct sockaddr_in6 *) sc->dst->ai_addr;
	memcpy(&ip->ip6_dst, &sin->sin6_addr, sizeof(struct in6_addr));

	/* We only send TCP/IP header portion. */
	sc->olen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);

	/* Prepare the checksum buffer. */
	struct cdata {
		struct in6_addr saddr;
		struct in6_addr daddr;
		u_int16_t length;
		u_int8_t buf[3];
		u_int8_t nexthdr;
		struct tcphdr tcp;
	} *cdata = (struct cdata *) sc->cbuf;
	memcpy(&cdata->saddr, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&cdata->daddr, &ip->ip6_dst, sizeof(struct in6_addr));
	cdata->buf[0] = cdata->buf[1] = cdata->buf[2] = 0;
	cdata->nexthdr = ip->ip6_nxt;
	cdata->length = htons(iphdrlen);
}
