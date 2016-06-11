#include "CppUTest/TestHarness.h"

extern "C"
{
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "scanner.h"
}

TEST_GROUP(ScannerTest)
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

TEST(ScannerTest, CheckTCPv4InitStartPort)
{
	LONGS_EQUAL(sc.ports.start, start_port);
}

TEST(ScannerTest, CheckTCPv4InitEndPort)
{
	LONGS_EQUAL(sc.ports.end, end_port);
}

TEST(ScannerTest, CheckTCPv4SourceAddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&sc.src;
	struct in_addr addr;
	inet_aton("127.0.0.1", &addr);

	LONGS_EQUAL(sin->sin_addr.s_addr, addr.s_addr);
}
