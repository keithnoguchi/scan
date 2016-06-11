#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>

#include "utils.h"
#include "scanner.h"

static void usage(const char *const progname)
{
	const char *const usage = "\
Usage: %s [-hdvx46] [-p port] [-i ifname] [-t sec] destination\n";

	fprintf(stderr, usage, progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	unsigned short start_port = 0;
	unsigned short end_port = 0;
	char *ifname = NULL;
	int domain = PF_INET;
	struct scanner sc;
	char *dstname;
	int port;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "hdvx46p:i:t:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			break;
		case 'd':
			debug_flag = true;
			break;
		case 'v':
			verbose_flag = true;
			break;
		case 'x':
			packet_dump_flag = true;
			break;
		case '4':
			domain = PF_INET;
			break;
		case '6':
			domain = PF_INET6;
			break;
		case 'p':
			port = atoi(optarg);
			if (port < 1 || port > UINT16_MAX)
				fprintf(stderr, "Invalid port, ignored\n");
			else
				start_port = end_port = port;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 't':
			duration_sec = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	/* Destination address/name. */
	dstname = argv[optind];

	/* Initialize the scanner with the hostname, address family,
	 * and the protocol. */
	ret = scanner_init(&sc, dstname, domain, IPPROTO_TCP, start_port,
			end_port, ifname);
	if (ret == -1)
		exit(EXIT_FAILURE);

	/* Light the fire! */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Done with the scanning. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}
