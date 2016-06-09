#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "utils.h"
#include "scanner.h"

/* Default variables. */
static const unsigned short scanner_default_start_port = 1;
static const unsigned short scanner_default_end_port = 65535;
static char *const scanner_default_ifname = NULL;

/* Command line flags. */
bool debug_flag = false;

static void usage(const char *const progname)
{
	fprintf(stderr, "Usage: %s [-d] <hostname> [-p port] [-i ifname]\n",
			progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	unsigned short start_port = scanner_default_start_port;
	unsigned short end_port = scanner_default_end_port;
	char *ifname = scanner_default_ifname;
	struct scanner sc;
	char *dstname;
	int port;
	int opt;

	while ((opt = getopt(argc, argv, "hdp:i:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			break;
		case 'd':
			debug_flag = true;
			break;
		case 'p':
			port = atoi(optarg);
			if (port <=0 || port > 65535)
				fprintf(stderr, "Invalid port, ignored\n");
			else
				start_port = end_port = port;
			break;
		case 'i':
			ifname = optarg;
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
	scanner_init(&sc, dstname, PF_INET, IPPROTO_TCP, start_port,
			end_port, ifname);

	/* Light the fire! */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Done with the scanning. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}
