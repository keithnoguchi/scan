#include "CppUTest/TestHarness.h"

extern "C"
{
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
	LONGS_EQUAL(sc.start_port, start_port);
}

TEST(ScannerTest, CheckTCPv4InitEndPort)
{
	LONGS_EQUAL(sc.end_port, end_port);
}
