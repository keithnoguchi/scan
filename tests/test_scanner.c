#include "CppUTest/TestHarness.h"

extern "C"
{
#include "scanner.h"
}

TEST_GROUP(ScannerTest)
{
	static const int start_port = 1;
	struct scanner sc;

	void setup()
	{
		scanner_init(&sc, "localhost", AF_INET,
				IPPROTO_TCP, start_port, 65535, "lo");
	}
	void teardown()
	{
		scanner_term(&sc);
	}
};

TEST(ScannerTest, CheckTCPv4InitializationStartPort)
{
	LONGS_EQUAL(sc.start_port, start_port);
}
