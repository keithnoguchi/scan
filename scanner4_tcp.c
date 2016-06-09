#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/tcp.h>

#include "utils.h"
#include "scanner.h"

static const size_t iphdrlen = 20;
static const size_t tcphdrlen = 20;

static int reader(struct scanner *sc)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sc->dst->ai_addr;
	struct tcphdr *tcp;
	struct iphdr *ip;
	int ret;

	ret = recv(sc->rawfd, sc->ibuf, sizeof(sc->ibuf), 0);
	if (ret < 0)
		fatal("recv(3)");

	/* Ignore packet less than 40(IP + TCP header size) bytes. */
	if (ret < iphdrlen + tcphdrlen)
		return 0;

	/* Drop the packet which is not from the destination. */
	ip = (struct iphdr *) sc->ibuf;
	if (ip->saddr != sin->sin_addr.s_addr) {
		debug("Drop packet not from the destination.\n");
		return 0;
	}

	debug("->\n");
	dump(sc->ibuf, ret);

	return ret;
}

static unsigned short tcp4_checksum(struct scanner *sc, struct tcphdr *tcp)
{
	struct cdata {
		u_int32_t saddr;
		u_int32_t daddr;
		u_int8_t buf;
		u_int8_t protocol;
		u_int16_t length;
		struct tcphdr tcp;
	} *cdata = (struct cdata *) sc->cbuf;
	cdata->tcp = *tcp;

	return checksum((uint16_t *) cdata, sizeof(struct cdata));
}

static int writer(struct scanner *sc)
{
	struct sockaddr_in *sin;
	struct tcphdr *tcp;
	struct iphdr *ip;
	int ret;

	debug("<-\n");

	/* IP header. */
	ip = (struct iphdr *) sc->obuf;
	ip->id = htonl(54321); /* randomize. */

	/* TCP header. */
	tcp = (struct tcphdr *)(sc->obuf + tcphdrlen);
	tcp->source = 0;
	tcp->dest = htons(sc->next_port);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->res1 = 0;
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->window = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;
	tcp->check = tcp4_checksum(sc, tcp);

	dump(sc->obuf, sc->olen);

	ret = sendto(sc->rawfd, sc->obuf, sc->olen, 0, sc->dst->ai_addr,
			sc->dst->ai_addrlen);
	if (ret != sc->olen)
		fatal("sendto()");

	if (++sc->next_port > sc->end_port) {
		/* Disable writer event. */
		sc->ev.events = EPOLLIN;
		epoll_ctl(sc->eventfd, EPOLL_CTL_MOD, sc->rawfd, &sc->ev);
		printf("done with sending\n");
	}

	return ret;
}

void scanner_tcp4_init(struct scanner *sc)
{
	struct sockaddr_in *sin;
	struct iphdr *ip;
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
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	sin = (struct sockaddr_in *) &sc->src;
	ip->saddr = sin->sin_addr.s_addr;
	sin = (struct sockaddr_in *) sc->dst->ai_addr;
	ip->daddr = sin->sin_addr.s_addr;

	/* We only send TCP/IP header portion. */
	sc->olen = sizeof(struct iphdr) + sizeof(struct tcphdr);

	/* Prepare the checksum buffer. */
	struct cdata {
		u_int32_t saddr;
		u_int32_t daddr;
		u_int8_t buf;
		u_int8_t protocol;
		u_int16_t length;
		struct tcphdr tcp;
	} *cdata = (struct cdata *) sc->cbuf;
	cdata->saddr = ip->saddr;
	cdata->daddr = ip->daddr;
	cdata->buf = 0;
	cdata->protocol = ip->protocol;
	cdata->length = htons(20);
}
