#include "CppUTest/TestHarness.h"

extern "C"
{
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "scanner.h"
}

TEST_GROUP(Scanner)
{
	static const int start_port = 22;
	static const int end_port = 69;
	struct scanner sc;

	void setup()
	{
		scanner_init(&sc, "localhost", AF_INET, IPPROTO_TCP,
				start_port, end_port, "lo");
	}
	void teardown()
	{
		scanner_term(&sc);
	}
};

TEST(Scanner, CheckTCPv4SourceAddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&sc.src;
	struct in_addr expected;

	inet_aton("127.0.0.1", &expected);
	LONGS_EQUAL(expected.s_addr, sin->sin_addr.s_addr);
}
